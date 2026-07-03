/* Parse OCI image references (REGISTRY/REPO[:TAG][@DIGEST])
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the de-facto containerd/docker reference grammar so that user
 * input like alpine, alpine:3.20, myuser/myrepo:tag, ghcr.io/owner/img:tag,
 * or repo@sha256:<hex> resolves to a canonical (registry, repository, tag,
 * digest) tuple. Defaults match Docker conventions: bare names land under
 * docker.io/library/ with tag latest.
 *
 * Grammar (informal):
 *
 *   reference := name [":" tag] ["@" digest]
 *   name      := [domain "/"] path
 *   domain    := first slash component containing "." or ":" or == "localhost"
 *   path      := component ("/" component)*
 *   component := [a-z0-9]+ ((["._-"] | "__") [a-z0-9]+)*
 *   tag       := [A-Za-z0-9_] [A-Za-z0-9_.-]{0,127}
 *   digest    := ("sha256" | "sha512") ":" hex   (lowercase hex)
 *
 * Domain detection follows containerd: the first slash-separated component
 * is treated as a registry only when it carries a domain marker. Bare
 * single-segment names (alpine) and two-segment names (user/repo) default
 * to docker.io. Single-segment defaults additionally pick up the library/
 * prefix.
 */

#pragma once

typedef struct {
    /* Registry hostname (and optional :port). Always non-NULL after parse. */
    char *registry;
    /* Repository path with namespace, e.g. "library/alpine". Always non-NULL.
     */
    char *repository;
    /* Tag name. NULL when the reference is pinned by digest only. Defaults
     * to "latest" when neither tag nor digest is present.
     */
    char *tag;
    /* Digest "<algo>:<hex>", or NULL. */
    char *digest;
} oci_ref_t;

/* Parse input into out. Returns 0 on success or -1 on malformed input. On
 * error, *err_msg (when err_msg != NULL) is set to a static description; the
 * string must not be freed. On success the caller owns out and must call
 * oci_ref_free.
 */
int oci_ref_parse(const char *input, oci_ref_t *out, const char **err_msg);

/* Render a canonical "registry/repository[:tag][@digest]" string. Always
 * heap-allocated; the caller frees. Returns NULL on allocation failure.
 */
char *oci_ref_canonical(const oci_ref_t *ref);

/* Render the canonical pin-name form "registry/repository:tag" used as the
 * value of the org.opencontainers.image.ref.name annotation in the store's
 * index.json. The digest segment is intentionally dropped: pin entries are
 * keyed by tag-name and the digest is stored separately in the descriptor.
 * Returns NULL with errno=EINVAL when ref->tag is unset (digest-only refs
 * are self-pinning and cannot be inserted into the pin table) or with
 * errno=ENOMEM on allocation failure. The caller frees the result.
 */
char *oci_ref_canonical_name(const oci_ref_t *ref);

/* Release any heap fields. Safe on a zero-initialised or partially populated
 * struct; resets all fields to NULL.
 */
void oci_ref_free(oci_ref_t *ref);
