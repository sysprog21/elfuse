/* Content digests for OCI image blobs
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wraps macOS CommonCrypto SHA-256 and SHA-512 in a streaming API so the
 * blob store and registry client can hash gigabyte-class layer downloads
 * without ever buffering the full payload in memory.
 *
 * Hex output is always lowercase; the OCI image reference parser already
 * rejects uppercase digest hex (see src/oci/ref.c), so every digest hex that
 * flows between the parser, the manifest fetcher, and the local store must
 * stay in the same canonical encoding to avoid silent dedup misses.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    OCI_DIGEST_SHA256,
    OCI_DIGEST_SHA512,
} oci_digest_algo_t;

/* Hex length per algorithm, excluding the trailing NUL. */
#define OCI_DIGEST_SHA256_HEX_LEN 64
#define OCI_DIGEST_SHA512_HEX_LEN 128
#define OCI_DIGEST_HEX_MAX OCI_DIGEST_SHA512_HEX_LEN

/* Opaque streaming digest. Allocated on the heap because the underlying
 * CommonCrypto context is moderately sized (SHA-512 keeps an 80-word state)
 * and callers tend to thread a digester pointer through several modules.
 */
typedef struct oci_digester oci_digester_t;

/* Allocate a streaming digester for algo. Returns NULL on bad enum or oom. */
oci_digester_t *oci_digester_new(oci_digest_algo_t algo);

/* Release a digester. Safe on NULL. */
void oci_digester_free(oci_digester_t *d);

/* Append data. Splits large buffers into CC_LONG-sized chunks internally
 * because CommonCrypto's update takes a uint32_t length and OCI layers can
 * exceed 4 GiB.
 */
void oci_digester_update(oci_digester_t *d, const void *buf, size_t len);

/* Finalize and write the lowercase hex string to out_hex. out_hex must hold
 * at least OCI_DIGEST_HEX_MAX + 1 bytes. Returns the hex length on success
 * (without trailing NUL) or 0 if d is NULL. The digester is consumed by this
 * call: the only valid next operation is oci_digester_free.
 */
size_t oci_digester_finish_hex(oci_digester_t *d, char *out_hex);

/* Lookup the algorithm name string ("sha256" / "sha512"). Returns NULL when
 * algo is out of range. The returned pointer is to static storage.
 */
const char *oci_digest_algo_name(oci_digest_algo_t algo);

/* Expected hex length for an algorithm (without trailing NUL). Returns 0 on
 * bad enum.
 */
size_t oci_digest_hex_len(oci_digest_algo_t algo);

/* Parse an algorithm name. Returns true and writes algo on match; false on
 * unknown name.
 */
bool oci_digest_algo_from_name(const char *name, oci_digest_algo_t *algo);

/* Validate that hex is exactly oci_digest_hex_len(algo) characters and that
 * every character is a lowercase hex digit. Rejects NULL.
 */
bool oci_digest_hex_valid(oci_digest_algo_t algo, const char *hex);

/* Parse "<algo>:<hex>" into algo and a canonical lowercase hex copy. The
 * input hex must already be lowercase; mixed case is rejected to match the
 * reference parser. out_hex must hold OCI_DIGEST_HEX_MAX + 1 bytes. On
 * success returns true; otherwise returns false and out_hex is left zeroed.
 */
bool oci_digest_parse(const char *colon_form,
                      oci_digest_algo_t *out_algo,
                      char *out_hex);

/* One-shot helper: compute algo over buf/len and emit lowercase hex into
 * out_hex (which must hold OCI_DIGEST_HEX_MAX + 1 bytes). Returns the hex
 * length on success or 0 on bad enum / NULL output.
 */
size_t oci_digest_bytes(oci_digest_algo_t algo,
                        const void *buf,
                        size_t len,
                        char *out_hex);

/* Compute the OCI image-spec ChainID for one layer in canonical
 * "<algo>:<hex>" form. ChainID is the cumulative content key used by the
 * stack cache: ChainID(L0) == DiffID(L0), and for any later
 * layer ChainID(Li) == sha256("<prev_chain> <diff_id>") where the input is
 * the previous chain string, an ASCII space (0x20), and the current layer's
 * diff_id string, both in their canonical "<algo>:<hex>" form. See OCI
 * image-spec v1.0.2 section 3.4 "Layer ChainID" for the reference text.
 *
 * The output is always sha256-prefixed regardless of diff_id's algorithm:
 * ChainID composition is defined over the textual digest representation, so
 * a sha512 diff_id contributes its full "sha512:<hex>" string but the result
 * is hashed with SHA-256 (the only ChainID algorithm the spec defines).
 *
 * Parameters:
 *   prev_chain  NULL signals the L0 case; the helper copies diff_id into
 *               out verbatim and returns 0. Non-NULL must be a valid
 *               "<algo>:<hex>" string in canonical lowercase form.
 *   diff_id     This layer's diff_id; must be non-NULL and "<algo>:<hex>".
 *   out         Receives the new ChainID string (NUL-terminated, always
 *               "sha256:<64-hex>" when prev_chain != NULL, or a copy of
 *               diff_id when prev_chain == NULL).
 *   cap         Capacity of out in bytes. Must be at least
 *               OCI_DIGEST_HEX_MAX + 16 so a sha512 diff_id fits in the L0
 *               passthrough path.
 *
 * Returns 0 on success, -1 with errno set on failure:
 *   EINVAL        diff_id NULL, prev_chain non-NULL but malformed, or
 *                 diff_id malformed
 *   ENAMETOOLONG  cap too small to hold the result
 *   ENOMEM        internal SHA-256 digester allocation failed
 */
int oci_chainid_compute(const char *prev_chain,
                        const char *diff_id,
                        char *out,
                        size_t cap);
