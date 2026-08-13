/*
 * Guest environment vector construction for the launch flags
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse builds the guest's "KEY=VALUE" array, which build_linux_stack copies
 * onto the initial guest stack, from the host environment plus the --env /
 * --clear-env flags, following `docker run -e` so an OCI front end can hand a
 * guest exactly the environment an image config asks for. The host
 * environment arrives as a parameter rather than from environ, so tests can
 * hand guest_env_build arbitrary base vectors, malformed entries included.
 */

#pragma once

#include <stdbool.h>

/* Build the guest environment vector from @host_env and the --env overrides.
 *
 * @host_env (NULL-terminated) fills two roles: the base the overrides merge
 * into (unless @clear_env), and the source a bare "KEY" override imports
 * from. They stay separate because `docker run -e KEY` imports from the
 * launcher's environment even when the base was cleared. NULL empties both.
 *
 * @overrides holds @n_overrides entries. "KEY=VALUE" replaces that key in
 * place when present and appends otherwise; a bare "KEY" imports the host
 * value, and a name the host does not set is skipped rather than imported as
 * empty. The value is everything after the first '='.
 *
 * On success returns 0. *out_envp is NULL when @n_overrides is 0 and
 * @clear_env is false, and the caller uses @host_env unchanged; otherwise it
 * is a malloc'd NULL-terminated array, entry count in *out_n, freed with
 * strv_free (src/utils.h). Every entry carries a '=' and a unique non-empty
 * name; @host_env entries violating that are dropped, or a later override
 * would append beside the entry it meant to replace. On allocation failure
 * or an empty override name (as setenv(3)) returns -1, logged, with the
 * outputs untouched.
 */
int guest_env_build(char *const *host_env,
                    char *const *overrides,
                    int n_overrides,
                    bool clear_env,
                    char ***out_envp,
                    int *out_n);
