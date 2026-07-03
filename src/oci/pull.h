/* `elfuse oci pull` — registry transfer via skopeo
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse does not carry its own registry protocol client. The store's
 * on-disk layout is the OCI image-layout spec (v1.0.0) precisely so
 * ecosystem tools can write it directly; pull shells out to skopeo,
 * which owns transport, authentication (skopeo login / docker
 * credential helpers), TLS policy (containers-policy.json,
 * registries.conf), and digest verification. elfuse's contribution is
 * the pin: the copied manifest digest is recorded in index.json under
 * the canonical ref name so inspect / unpack / run can reproduce the
 * pull by name, exactly as before.
 */

#pragma once

#include <stdbool.h>

#include "ref.h"
#include "store.h"

typedef struct {
    /* Suppress skopeo's progress output (maps to `skopeo copy -q`). */
    bool quiet;
    /* Guest architecture to resolve multi-arch references to. NULL
     * defaults to "arm64"; pass "amd64" for Rosetta-run x86_64 images.
     */
    const char *arch;
} oci_pull_options_t;

/* Copy ref into the store via `skopeo copy` and pin the resulting
 * manifest digest under the canonical ref name. store_root must be the
 * same directory store was opened on (skopeo needs the path, the pin
 * needs the handle). Digest-pinned refs skip the pin step: they are
 * self-describing and oci_store_put_ref refuses them by design.
 *
 * Returns 0 on success; -1 with errno set and *err_msg (when non-NULL)
 * pointing at a static or thread-local description. A missing skopeo
 * binary surfaces ENOENT with an install hint.
 */
int oci_pull(oci_store_t *store,
             const char *store_root,
             const oci_ref_t *ref,
             const oci_pull_options_t *opts,
             const char **err_msg);
