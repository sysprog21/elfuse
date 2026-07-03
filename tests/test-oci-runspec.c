/* OCI runspec resolver unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives oci_runspec_build against hand-built oci_image_runtime_t literals
 * and synthetic host environs. Every case is a pure data check, no
 * filesystem touches, no spawned processes; the runspec module exists
 * exactly so the override-matrix and Env-policy logic can be verified
 * deterministically without the rest of the oci run orchestration in the
 * loop.
 *
 * Coverage areas (issue #31 acceptance 2/3/4/5):
 *   - Argv override matrix: each of the eight rows documented in
 *     runspec.h
 *   - Env merge: image Env baseline, CLI -e KEY=VAL set/replace,
 *     bare -e KEY host import (hit + miss), TERM auto-import gate,
 *     default PATH gate, container=elfuse forced injection
 *   - DYLD_* hard rejection on CLI overrides
 *   - User: numeric UID, UID:GID, image User, CLI --user precedence,
 *     symbolic User with rootfs_for_nss + the variant gid shapes,
 *     symbolic User without rootfs hard-fail, name-not-found diagnostic
 *   - WorkingDir: image-only, override-only, default, relative reject,
 *     "..\" segment reject
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oci/manifest.h"
#include "oci/runspec.h"

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

/* Construct a NULL-terminated char ** from a brace-list of string literals.
 * The literals live in .rodata; the runspec builder strdups them, so this
 * is safe to feed into oci_image_runtime_t.entrypoint / .cmd / .env.
 */
#define STR_ARR(...) ((char *[]) {__VA_ARGS__, NULL})

/* Length of a NULL-terminated string vector. */
static size_t vec_len(char *const *v)
{
    if (!v)
        return 0;
    size_t n = 0;
    while (v[n])
        n++;
    return n;
}

static bool vec_contains(char *const *v, const char *needle)
{
    for (size_t i = 0; v && v[i]; i++) {
        if (strcmp(v[i], needle) == 0)
            return true;
    }
    return false;
}

static const char *vec_get(char *const *v, size_t i)
{
    return (v && i < vec_len(v)) ? v[i] : "(missing)";
}

/* Find env entry by KEY and return value pointer, or NULL. */
static const char *env_get(char *const *envp, const char *key)
{
    size_t klen = strlen(key);
    for (size_t i = 0; envp && envp[i]; i++) {
        if (strncmp(envp[i], key, klen) == 0 && envp[i][klen] == '=')
            return envp[i] + klen + 1;
    }
    return NULL;
}

/* Minimal host environ literal for cases that exercise host import. */
static const char *const HOST_BASIC[] = {
    "TERM=xterm-256color",
    "USER=tester",
    "LANG=en_US.UTF-8",
    NULL,
};

/* Host environ with no TERM, used for the auto-import-gate negative case. */
static const char *const HOST_NO_TERM[] = {
    "USER=tester",
    "LANG=en_US.UTF-8",
    NULL,
};

/* Convenience: zero-init flags struct. */
static oci_runspec_flags_t empty_flags(void)
{
    return (oci_runspec_flags_t) {0};
}

/* ── Argv override matrix ──────────────────────────────────────────── */

static void case_argv_entrypoint_plus_cmd(void)
{
    const char *name = "argv: image Entrypoint ++ Cmd when CLI args absent";
    oci_image_runtime_t cfg = {
        .entrypoint = STR_ARR("/entry"),
        .cmd = STR_ARR("arg1", "arg2"),
    };
    oci_runspec_flags_t flags = empty_flags();
    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(null)");
    } else if (vec_len(spec.argv) != 3) {
        report_fail(name, "argv len=%zu want 3", vec_len(spec.argv));
    } else if (strcmp(vec_get(spec.argv, 0), "/entry") != 0 ||
               strcmp(vec_get(spec.argv, 1), "arg1") != 0 ||
               strcmp(vec_get(spec.argv, 2), "arg2") != 0) {
        report_fail(name, "argv = [%s, %s, %s]", vec_get(spec.argv, 0),
                    vec_get(spec.argv, 1), vec_get(spec.argv, 2));
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_argv_entrypoint_plus_cli_drops_cmd(void)
{
    const char *name = "argv: image Entrypoint ++ CLI args drops image Cmd";
    oci_image_runtime_t cfg = {
        .entrypoint = STR_ARR("/entry"),
        .cmd = STR_ARR("default-arg"),
    };
    const char *const cli_argv[] = {"override-a", "override-b"};
    oci_runspec_flags_t flags = empty_flags();
    flags.positional_argc = 2;
    flags.positional_argv = cli_argv;

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(null)");
    } else if (vec_len(spec.argv) != 3) {
        report_fail(name, "argv len=%zu want 3", vec_len(spec.argv));
    } else if (vec_contains(spec.argv, "default-arg")) {
        report_fail(name, "image Cmd 'default-arg' leaked into argv");
    } else if (strcmp(vec_get(spec.argv, 0), "/entry") != 0 ||
               strcmp(vec_get(spec.argv, 1), "override-a") != 0 ||
               strcmp(vec_get(spec.argv, 2), "override-b") != 0) {
        report_fail(name, "argv = [%s, %s, %s]", vec_get(spec.argv, 0),
                    vec_get(spec.argv, 1), vec_get(spec.argv, 2));
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_argv_entrypoint_only_plus_cli(void)
{
    const char *name = "argv: image Entrypoint (no Cmd) ++ CLI args";
    oci_image_runtime_t cfg = {.entrypoint = STR_ARR("/entry")};
    const char *const cli_argv[] = {"arg"};
    oci_runspec_flags_t flags = empty_flags();
    flags.positional_argc = 1;
    flags.positional_argv = cli_argv;

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || vec_len(spec.argv) != 2 ||
        strcmp(vec_get(spec.argv, 0), "/entry") != 0 ||
        strcmp(vec_get(spec.argv, 1), "arg") != 0) {
        report_fail(name, "rc=%d argv=[%s,%s]", rc, vec_get(spec.argv, 0),
                    vec_get(spec.argv, 1));
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_argv_cmd_only_no_cli(void)
{
    const char *name = "argv: image Cmd alone when no Entrypoint, no CLI";
    oci_image_runtime_t cfg = {.cmd = STR_ARR("/bin/sh", "-c", "echo hi")};
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || vec_len(spec.argv) != 3 ||
        strcmp(vec_get(spec.argv, 0), "/bin/sh") != 0 ||
        strcmp(vec_get(spec.argv, 2), "echo hi") != 0) {
        report_fail(name, "rc=%d argv head=%s tail=%s", rc,
                    vec_get(spec.argv, 0), vec_get(spec.argv, 2));
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_argv_cli_replaces_cmd(void)
{
    const char *name = "argv: CLI args replace image Cmd when no Entrypoint";
    oci_image_runtime_t cfg = {.cmd = STR_ARR("ignored")};
    const char *const cli_argv[] = {"chosen"};
    oci_runspec_flags_t flags = empty_flags();
    flags.positional_argc = 1;
    flags.positional_argv = cli_argv;

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || vec_len(spec.argv) != 1 ||
        strcmp(vec_get(spec.argv, 0), "chosen") != 0 ||
        vec_contains(spec.argv, "ignored")) {
        report_fail(name, "rc=%d argv0=%s", rc, vec_get(spec.argv, 0));
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_argv_entrypoint_override(void)
{
    const char *name =
        "argv: --entrypoint clobbers both image Entrypoint and Cmd";
    oci_image_runtime_t cfg = {
        .entrypoint = STR_ARR("/img-entry"),
        .cmd = STR_ARR("img-cmd"),
    };
    const char *const cli_argv[] = {"cli1", "cli2"};
    oci_runspec_flags_t flags = empty_flags();
    flags.entrypoint_override = "/new-entry";
    flags.positional_argc = 2;
    flags.positional_argv = cli_argv;

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || vec_len(spec.argv) != 3 ||
        strcmp(vec_get(spec.argv, 0), "/new-entry") != 0 ||
        strcmp(vec_get(spec.argv, 1), "cli1") != 0 ||
        strcmp(vec_get(spec.argv, 2), "cli2") != 0 ||
        vec_contains(spec.argv, "/img-entry") ||
        vec_contains(spec.argv, "img-cmd")) {
        report_fail(name, "rc=%d argv=[%s,%s,%s]", rc, vec_get(spec.argv, 0),
                    vec_get(spec.argv, 1), vec_get(spec.argv, 2));
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_argv_cli_only_no_image_fields(void)
{
    const char *name =
        "argv: image has neither Entrypoint nor Cmd, CLI provides argv";
    oci_image_runtime_t cfg = {0};
    const char *const cli_argv[] = {"/bin/echo", "hi"};
    oci_runspec_flags_t flags = empty_flags();
    flags.positional_argc = 2;
    flags.positional_argv = cli_argv;

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || vec_len(spec.argv) != 2 ||
        strcmp(vec_get(spec.argv, 0), "/bin/echo") != 0 ||
        strcmp(vec_get(spec.argv, 1), "hi") != 0) {
        report_fail(name, "rc=%d argv=[%s,%s]", rc, vec_get(spec.argv, 0),
                    vec_get(spec.argv, 1));
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_argv_einval_no_source(void)
{
    const char *name =
        "argv: EINVAL when image has no Entrypoint or Cmd and CLI is empty";
    oci_image_runtime_t cfg = {0};
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    errno = 0;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != -1) {
        report_fail(name, "rc=%d (want -1)", rc);
    } else if (errno != EINVAL) {
        report_fail(name, "errno=%d (want EINVAL)", errno);
    } else if (!err || !strstr(err, "no entrypoint or cmd")) {
        report_fail(name, "err=%s", err ? err : "(null)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

/* ── Env merge ─────────────────────────────────────────────────────── */

static void case_env_image_baseline(void)
{
    const char *name =
        "env: image Env passes through verbatim; container=elfuse appended";
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .env = STR_ARR("FOO=1", "BAR=baz"),
    };
    oci_runspec_flags_t flags = empty_flags();
    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    const char *foo = env_get(spec.envp, "FOO");
    const char *bar = env_get(spec.envp, "BAR");
    const char *container = env_get(spec.envp, "container");
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(null)");
    } else if (!foo || strcmp(foo, "1") != 0) {
        report_fail(name, "FOO=%s", foo ? foo : "(missing)");
    } else if (!bar || strcmp(bar, "baz") != 0) {
        report_fail(name, "BAR=%s", bar ? bar : "(missing)");
    } else if (!container || strcmp(container, "elfuse") != 0) {
        report_fail(name, "container=%s", container ? container : "(missing)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_env_cli_kv_replaces(void)
{
    const char *name = "env: -e KEY=VAL replaces image-provided KEY";
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .env = STR_ARR("FOO=image", "KEEP=alive"),
    };
    const char *const overrides[] = {"FOO=cli"};
    oci_runspec_flags_t flags = empty_flags();
    flags.env_overrides = overrides;
    flags.nenv_overrides = 1;

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    const char *foo = env_get(spec.envp, "FOO");
    const char *keep = env_get(spec.envp, "KEEP");
    if (rc != 0 || !foo || strcmp(foo, "cli") != 0 || !keep ||
        strcmp(keep, "alive") != 0) {
        report_fail(name, "rc=%d FOO=%s KEEP=%s", rc, foo ? foo : "(missing)",
                    keep ? keep : "(missing)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_env_host_import_hit(void)
{
    const char *name =
        "env: bare -e KEY imports from host environ when present";
    oci_image_runtime_t cfg = {.cmd = STR_ARR("/bin/echo")};
    const char *const overrides[] = {"USER"};
    oci_runspec_flags_t flags = empty_flags();
    flags.env_overrides = overrides;
    flags.nenv_overrides = 1;

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    const char *user = env_get(spec.envp, "USER");
    if (rc != 0 || !user || strcmp(user, "tester") != 0) {
        report_fail(name, "rc=%d USER=%s", rc, user ? user : "(missing)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_env_host_import_miss(void)
{
    const char *name = "env: bare -e KEY silently drops when host has no KEY";
    oci_image_runtime_t cfg = {.cmd = STR_ARR("/bin/echo")};
    const char *const overrides[] = {"NEVER_SET_THIS_KEY"};
    oci_runspec_flags_t flags = empty_flags();
    flags.env_overrides = overrides;
    flags.nenv_overrides = 1;

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(null)");
    } else if (env_get(spec.envp, "NEVER_SET_THIS_KEY")) {
        report_fail(name, "missing host KEY should not appear in envp");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_env_term_auto_import(void)
{
    const char *name =
        "env: TERM auto-imported from host when image leaves it unset";
    oci_image_runtime_t cfg = {.cmd = STR_ARR("/bin/echo")};
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    const char *term = env_get(spec.envp, "TERM");
    if (rc != 0 || !term || strcmp(term, "xterm-256color") != 0) {
        report_fail(name, "rc=%d TERM=%s", rc, term ? term : "(missing)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_env_term_no_host(void)
{
    const char *name = "env: TERM auto-import is a no-op when host has no TERM";
    oci_image_runtime_t cfg = {.cmd = STR_ARR("/bin/echo")};
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_NO_TERM, &spec, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(null)");
    } else if (env_get(spec.envp, "TERM")) {
        report_fail(name, "TERM appeared in envp despite missing host TERM");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_env_term_image_keeps(void)
{
    const char *name =
        "env: image-provided TERM is kept; host TERM does not overwrite it";
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .env = STR_ARR("TERM=dumb"),
    };
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    const char *term = env_get(spec.envp, "TERM");
    if (rc != 0 || !term || strcmp(term, "dumb") != 0) {
        report_fail(name, "rc=%d TERM=%s", rc, term ? term : "(missing)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_env_default_path_injected(void)
{
    const char *name =
        "env: Linux default PATH injected when image config omits it";
    oci_image_runtime_t cfg = {.cmd = STR_ARR("/bin/echo")};
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    const char *path = env_get(spec.envp, "PATH");
    if (rc != 0 || !path ||
        strcmp(path,
               "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
               "/sbin:/bin") != 0) {
        report_fail(name, "rc=%d PATH=%s", rc, path ? path : "(missing)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_env_image_path_preserved(void)
{
    const char *name = "env: image-supplied PATH is preserved verbatim";
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .env = STR_ARR("PATH=/custom/bin"),
    };
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    const char *path = env_get(spec.envp, "PATH");
    if (rc != 0 || !path || strcmp(path, "/custom/bin") != 0) {
        report_fail(name, "rc=%d PATH=%s", rc, path ? path : "(missing)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_env_container_always_set(void)
{
    const char *name =
        "env: container=elfuse forced over any image-supplied container=";
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .env = STR_ARR("container=docker"),
    };
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    const char *container = env_get(spec.envp, "container");
    if (rc != 0 || !container || strcmp(container, "elfuse") != 0) {
        report_fail(name, "rc=%d container=%s", rc,
                    container ? container : "(missing)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_env_dyld_rejected(void)
{
    const char *name = "env: -e DYLD_INSERT_LIBRARIES=... rejected with EINVAL";
    oci_image_runtime_t cfg = {.cmd = STR_ARR("/bin/echo")};
    const char *const overrides[] = {"DYLD_INSERT_LIBRARIES=/x.dylib"};
    oci_runspec_flags_t flags = empty_flags();
    flags.env_overrides = overrides;
    flags.nenv_overrides = 1;

    oci_runspec_t spec = {0};
    const char *err = NULL;
    errno = 0;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != -1) {
        report_fail(name, "rc=%d (want -1)", rc);
    } else if (errno != EINVAL) {
        report_fail(name, "errno=%d (want EINVAL)", errno);
    } else if (!err || !strstr(err, "DYLD_") ||
               !strstr(err, "DYLD_INSERT_LIBRARIES")) {
        report_fail(name, "err=%s", err ? err : "(null)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

/* ── User ──────────────────────────────────────────────────────────── */

static void case_user_image_uid_only(void)
{
    const char *name =
        "user: image User '1000' parses to uid=1000 with gid falling through";
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .user = "1000",
    };
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || !spec.has_creds || spec.uid != 1000 || spec.gid != 1000) {
        report_fail(name, "rc=%d has=%d uid=%u gid=%u", rc, spec.has_creds,
                    spec.uid, spec.gid);
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_user_image_uid_gid(void)
{
    const char *name = "user: image User '1000:5000' splits uid/gid";
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .user = "1000:5000",
    };
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || !spec.has_creds || spec.uid != 1000 || spec.gid != 5000) {
        report_fail(name, "rc=%d has=%d uid=%u gid=%u", rc, spec.has_creds,
                    spec.uid, spec.gid);
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_user_cli_overrides_image(void)
{
    const char *name = "user: CLI --user takes precedence over image User";
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .user = "1000",
    };
    oci_runspec_flags_t flags = empty_flags();
    flags.user_override = "42:43";

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || !spec.has_creds || spec.uid != 42 || spec.gid != 43) {
        report_fail(name, "rc=%d has=%d uid=%u gid=%u", rc, spec.has_creds,
                    spec.uid, spec.gid);
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_user_no_creds_inherits(void)
{
    const char *name =
        "user: no image User and no --user yields has_creds=false";
    oci_image_runtime_t cfg = {.cmd = STR_ARR("/bin/echo")};
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || spec.has_creds) {
        report_fail(name, "rc=%d has_creds=%d", rc, spec.has_creds);
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_user_symbolic_no_rootfs_rejected(void)
{
    const char *name =
        "user: symbolic image User without rootfs_for_nss -> EINVAL";
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .user = "nginx",
    };
    /* rootfs_for_nss defaults to NULL: the resolver must reject the
     * symbolic token rather than reach into the host filesystem. */
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    errno = 0;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != -1) {
        report_fail(name, "rc=%d (want -1)", rc);
    } else if (errno != EINVAL) {
        report_fail(name, "errno=%d (want EINVAL)", errno);
    } else if (!err || !strstr(err, "'nginx'") || !strstr(err, "no rootfs")) {
        report_fail(name, "err=%s", err ? err : "(null)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_user_cli_non_numeric(void)
{
    /* Without rootfs_for_nss the CLI symbolic token must surface as a
     * "no rootfs available" diagnostic so the user can tell why their
     * --user alice rejection has nothing to do with parsing.
     */
    const char *name =
        "user: --user 'alice' without rootfs -> EINVAL no-rootfs";
    oci_image_runtime_t cfg = {.cmd = STR_ARR("/bin/echo")};
    oci_runspec_flags_t flags = empty_flags();
    flags.user_override = "alice";

    oci_runspec_t spec = {0};
    const char *err = NULL;
    errno = 0;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != -1 || errno != EINVAL || !err || !strstr(err, "--user 'alice'") ||
        !strstr(err, "no rootfs")) {
        report_fail(name, "rc=%d errno=%d err=%s", rc, errno,
                    err ? err : "(null)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

/* Helpers for the rootfs-driven symbolic cases. Each case builds a small
 * scratch rootfs under /tmp with synthetic /etc/passwd and /etc/group
 * fixtures, drives the resolver, then tears the rootfs down. The
 * fixtures mirror the layout test-oci-user.c uses so the two test
 * binaries agree on the resolver's interpretation.
 */
static int rs_write_file(const char *path, const char *body)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    size_t n = strlen(body);
    if (write(fd, body, n) != (ssize_t) n) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static void rs_rmrf(const char *path)
{
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
    (void) system(cmd);
}

static int rs_make_rootfs_with_passwd(char *out,
                                      size_t cap,
                                      const char *passwd_body,
                                      const char *group_body)
{
    snprintf(out, cap, "/tmp/elfuse-rs-XXXXXX");
    if (!mkdtemp(out))
        return -1;
    char etc[256];
    snprintf(etc, sizeof(etc), "%s/etc", out);
    if (mkdir(etc, 0755) < 0)
        return -1;
    char path[512];
    if (passwd_body) {
        snprintf(path, sizeof(path), "%s/etc/passwd", out);
        if (rs_write_file(path, passwd_body) < 0)
            return -1;
    }
    if (group_body) {
        snprintf(path, sizeof(path), "%s/etc/group", out);
        if (rs_write_file(path, group_body) < 0)
            return -1;
    }
    return 0;
}

static const char *const RS_PASSWD_BODY =
    "root:x:0:0:root:/root:/bin/sh\n"
    "nginx:x:101:103:nginx:/var/lib/nginx:/sbin/nologin\n"
    "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n";

static const char *const RS_GROUP_BODY =
    "root:x:0:\n"
    "adm:x:4:alice\n"
    "nginx:x:103:\n";

static void case_user_image_symbolic_with_rootfs(void)
{
    const char *name =
        "user: image User 'nginx' resolved via rootfs -> uid=101, gid=103";
    char rootfs[64];
    if (rs_make_rootfs_with_passwd(rootfs, sizeof(rootfs), RS_PASSWD_BODY,
                                   RS_GROUP_BODY) < 0) {
        report_fail(name, "rootfs setup failed: errno=%d", errno);
        return;
    }
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .user = "nginx",
    };
    oci_runspec_flags_t flags = empty_flags();
    flags.rootfs_for_nss = rootfs;

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || !spec.has_creds || spec.uid != 101 || spec.gid != 103) {
        report_fail(name, "rc=%d has=%d uid=%u gid=%u err=%s", rc,
                    spec.has_creds, spec.uid, spec.gid, err ? err : "(nil)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
    rs_rmrf(rootfs);
}

static void case_user_cli_symbolic_overrides_image_numeric(void)
{
    const char *name =
        "user: --user 'alice:adm' overrides numeric image User "
        "(uid=1000,gid=4)";
    char rootfs[64];
    if (rs_make_rootfs_with_passwd(rootfs, sizeof(rootfs), RS_PASSWD_BODY,
                                   RS_GROUP_BODY) < 0) {
        report_fail(name, "rootfs setup failed: errno=%d", errno);
        return;
    }
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .user = "9999",
    };
    oci_runspec_flags_t flags = empty_flags();
    flags.user_override = "alice:adm";
    flags.rootfs_for_nss = rootfs;

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || !spec.has_creds || spec.uid != 1000 || spec.gid != 4) {
        report_fail(name, "rc=%d has=%d uid=%u gid=%u err=%s", rc,
                    spec.has_creds, spec.uid, spec.gid, err ? err : "(nil)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
    rs_rmrf(rootfs);
}

static void case_user_missing_passwd_with_symbolic(void)
{
    const char *name =
        "user: symbolic User but rootfs has no /etc/passwd -> EINVAL";
    char rootfs[64];
    /* No passwd / group files: just the bare /etc directory. */
    if (rs_make_rootfs_with_passwd(rootfs, sizeof(rootfs), NULL, NULL) < 0) {
        report_fail(name, "rootfs setup failed: errno=%d", errno);
        return;
    }
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .user = "nginx",
    };
    oci_runspec_flags_t flags = empty_flags();
    flags.rootfs_for_nss = rootfs;

    oci_runspec_t spec = {0};
    const char *err = NULL;
    errno = 0;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != -1) {
        report_fail(name, "rc=%d (want -1)", rc);
    } else if (!err || !strstr(err, "'nginx'") || !strstr(err, "/etc/passwd")) {
        report_fail(name, "err=%s (want 'nginx' + '/etc/passwd')",
                    err ? err : "(nil)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
    rs_rmrf(rootfs);
}

/* ── WorkingDir ────────────────────────────────────────────────────── */

static void case_workdir_image_used(void)
{
    const char *name = "workdir: image WorkingDir used when CLI omits -w";
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .working_dir = "/srv/app",
    };
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || !spec.cwd || strcmp(spec.cwd, "/srv/app") != 0) {
        report_fail(name, "rc=%d cwd=%s", rc, spec.cwd ? spec.cwd : "(null)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_workdir_cli_override(void)
{
    const char *name = "workdir: CLI -w overrides image WorkingDir";
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .working_dir = "/img",
    };
    oci_runspec_flags_t flags = empty_flags();
    flags.workdir_override = "/cli";

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || !spec.cwd || strcmp(spec.cwd, "/cli") != 0) {
        report_fail(name, "rc=%d cwd=%s", rc, spec.cwd ? spec.cwd : "(null)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_workdir_default_root(void)
{
    const char *name =
        "workdir: defaults to '/' when neither image nor CLI sets it";
    oci_image_runtime_t cfg = {.cmd = STR_ARR("/bin/echo")};
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != 0 || !spec.cwd || strcmp(spec.cwd, "/") != 0) {
        report_fail(name, "rc=%d cwd=%s", rc, spec.cwd ? spec.cwd : "(null)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_workdir_relative_rejected(void)
{
    const char *name = "workdir: relative path 'foo/bar' rejected with EINVAL";
    oci_image_runtime_t cfg = {.cmd = STR_ARR("/bin/echo")};
    oci_runspec_flags_t flags = empty_flags();
    flags.workdir_override = "foo/bar";

    oci_runspec_t spec = {0};
    const char *err = NULL;
    errno = 0;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != -1 || errno != EINVAL || !err ||
        !strstr(err, "WorkingDir must be absolute") ||
        !strstr(err, "foo/bar")) {
        report_fail(name, "rc=%d errno=%d err=%s", rc, errno,
                    err ? err : "(null)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

static void case_workdir_dotdot_rejected(void)
{
    const char *name =
        "workdir: '..' segment in '/srv/../etc' rejected with EINVAL";
    oci_image_runtime_t cfg = {
        .cmd = STR_ARR("/bin/echo"),
        .working_dir = "/srv/../etc",
    };
    oci_runspec_flags_t flags = empty_flags();

    oci_runspec_t spec = {0};
    const char *err = NULL;
    errno = 0;
    int rc = oci_runspec_build(&cfg, &flags, HOST_BASIC, &spec, &err);
    if (rc != -1 || errno != EINVAL || !err || !strstr(err, "'..'") ||
        !strstr(err, "/srv/../etc")) {
        report_fail(name, "rc=%d errno=%d err=%s", rc, errno,
                    err ? err : "(null)");
    } else {
        report_pass(name);
    }
    oci_runspec_free(&spec);
}

int main(void)
{
    printf("OCI runspec resolver unit tests\n");

    /* Argv override matrix */
    case_argv_entrypoint_plus_cmd();
    case_argv_entrypoint_plus_cli_drops_cmd();
    case_argv_entrypoint_only_plus_cli();
    case_argv_cmd_only_no_cli();
    case_argv_cli_replaces_cmd();
    case_argv_entrypoint_override();
    case_argv_cli_only_no_image_fields();
    case_argv_einval_no_source();

    /* Env merge */
    case_env_image_baseline();
    case_env_cli_kv_replaces();
    case_env_host_import_hit();
    case_env_host_import_miss();
    case_env_term_auto_import();
    case_env_term_no_host();
    case_env_term_image_keeps();
    case_env_default_path_injected();
    case_env_image_path_preserved();
    case_env_container_always_set();
    case_env_dyld_rejected();

    /* User */
    case_user_image_uid_only();
    case_user_image_uid_gid();
    case_user_cli_overrides_image();
    case_user_no_creds_inherits();
    case_user_symbolic_no_rootfs_rejected();
    case_user_cli_non_numeric();
    case_user_image_symbolic_with_rootfs();
    case_user_cli_symbolic_overrides_image_numeric();
    case_user_missing_passwd_with_symbolic();

    /* WorkingDir */
    case_workdir_image_used();
    case_workdir_cli_override();
    case_workdir_default_root();
    case_workdir_relative_rejected();
    case_workdir_dotdot_rejected();

    printf("\nResults: %d/%d passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
