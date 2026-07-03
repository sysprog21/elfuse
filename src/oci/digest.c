/* Content digests for OCI image blobs
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "digest.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* CC_LONG is 32-bit; clamp every update call so multi-gigabyte layers cannot
 * overflow the CommonCrypto length argument silently. 1 GiB is well below the
 * limit and large enough that the per-call overhead is negligible.
 */
#define DIGESTER_CHUNK_MAX ((size_t) (1u << 30))

struct oci_digester {
    oci_digest_algo_t algo;
    union {
        CC_SHA256_CTX sha256;
        CC_SHA512_CTX sha512;
    } ctx;
};

static const char HEX_LOWER[] = "0123456789abcdef";

static void bin_to_hex_lower(const uint8_t *bin, size_t bin_len, char *out)
{
    for (size_t i = 0; i < bin_len; i++) {
        out[i * 2] = HEX_LOWER[(bin[i] >> 4) & 0xf];
        out[i * 2 + 1] = HEX_LOWER[bin[i] & 0xf];
    }
    out[bin_len * 2] = '\0';
}

const char *oci_digest_algo_name(oci_digest_algo_t algo)
{
    switch (algo) {
    case OCI_DIGEST_SHA256:
        return "sha256";
    case OCI_DIGEST_SHA512:
        return "sha512";
    }
    return NULL;
}

size_t oci_digest_hex_len(oci_digest_algo_t algo)
{
    switch (algo) {
    case OCI_DIGEST_SHA256:
        return OCI_DIGEST_SHA256_HEX_LEN;
    case OCI_DIGEST_SHA512:
        return OCI_DIGEST_SHA512_HEX_LEN;
    }
    return 0;
}

bool oci_digest_algo_from_name(const char *name, oci_digest_algo_t *algo)
{
    if (!name || !algo)
        return false;
    if (!strcmp(name, "sha256")) {
        *algo = OCI_DIGEST_SHA256;
        return true;
    }
    if (!strcmp(name, "sha512")) {
        *algo = OCI_DIGEST_SHA512;
        return true;
    }
    return false;
}

bool oci_digest_hex_valid(oci_digest_algo_t algo, const char *hex)
{
    if (!hex)
        return false;
    size_t want = oci_digest_hex_len(algo);
    if (want == 0)
        return false;
    if (strlen(hex) != want)
        return false;
    for (size_t i = 0; i < want; i++) {
        char c = hex[i];
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok)
            return false;
    }
    return true;
}

bool oci_digest_parse(const char *colon_form,
                      oci_digest_algo_t *out_algo,
                      char *out_hex)
{
    if (!colon_form || !out_algo || !out_hex)
        return false;

    out_hex[0] = '\0';
    const char *colon = strchr(colon_form, ':');
    if (!colon || colon == colon_form)
        return false;

    char name[8];
    size_t name_len = (size_t) (colon - colon_form);
    if (name_len >= sizeof(name))
        return false;
    memcpy(name, colon_form, name_len);
    name[name_len] = '\0';

    oci_digest_algo_t algo;
    if (!oci_digest_algo_from_name(name, &algo))
        return false;

    const char *hex = colon + 1;
    if (!oci_digest_hex_valid(algo, hex))
        return false;

    *out_algo = algo;
    memcpy(out_hex, hex, oci_digest_hex_len(algo) + 1);
    return true;
}

oci_digester_t *oci_digester_new(oci_digest_algo_t algo)
{
    oci_digester_t *d = calloc(1, sizeof(*d));
    if (!d)
        return NULL;
    d->algo = algo;
    switch (algo) {
    case OCI_DIGEST_SHA256:
        (void) CC_SHA256_Init(&d->ctx.sha256);
        break;
    case OCI_DIGEST_SHA512:
        (void) CC_SHA512_Init(&d->ctx.sha512);
        break;
    default:
        free(d);
        return NULL;
    }
    return d;
}

void oci_digester_free(oci_digester_t *d)
{
    free(d);
}

void oci_digester_update(oci_digester_t *d, const void *buf, size_t len)
{
    if (!d || !buf || len == 0)
        return;
    const uint8_t *p = buf;
    while (len > 0) {
        size_t chunk = len > DIGESTER_CHUNK_MAX ? DIGESTER_CHUNK_MAX : len;
        switch (d->algo) {
        case OCI_DIGEST_SHA256:
            (void) CC_SHA256_Update(&d->ctx.sha256, p, (CC_LONG) chunk);
            break;
        case OCI_DIGEST_SHA512:
            (void) CC_SHA512_Update(&d->ctx.sha512, p, (CC_LONG) chunk);
            break;
        }
        p += chunk;
        len -= chunk;
    }
}

size_t oci_digester_finish_hex(oci_digester_t *d, char *out_hex)
{
    if (!d || !out_hex)
        return 0;
    uint8_t md[CC_SHA512_DIGEST_LENGTH];
    size_t bin_len = 0;
    switch (d->algo) {
    case OCI_DIGEST_SHA256:
        (void) CC_SHA256_Final(md, &d->ctx.sha256);
        bin_len = CC_SHA256_DIGEST_LENGTH;
        break;
    case OCI_DIGEST_SHA512:
        (void) CC_SHA512_Final(md, &d->ctx.sha512);
        bin_len = CC_SHA512_DIGEST_LENGTH;
        break;
    default:
        return 0;
    }
    bin_to_hex_lower(md, bin_len, out_hex);
    return bin_len * 2;
}

size_t oci_digest_bytes(oci_digest_algo_t algo,
                        const void *buf,
                        size_t len,
                        char *out_hex)
{
    if (!out_hex)
        return 0;
    oci_digester_t *d = oci_digester_new(algo);
    if (!d)
        return 0;
    oci_digester_update(d, buf, len);
    size_t n = oci_digester_finish_hex(d, out_hex);
    oci_digester_free(d);
    return n;
}

int oci_chainid_compute(const char *prev_chain,
                        const char *diff_id,
                        char *out,
                        size_t cap)
{
    if (!diff_id || !out || cap == 0) {
        errno = EINVAL;
        return -1;
    }

    /* Validate the diff_id is well-formed before any hashing so the L0
     * passthrough path and the Li hash path agree on input validation.
     */
    oci_digest_algo_t diff_algo;
    char diff_hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(diff_id, &diff_algo, diff_hex)) {
        errno = EINVAL;
        return -1;
    }

    if (!prev_chain) {
        /* L0 case: ChainID(L0) == DiffID(L0). Copy verbatim so a sha512
         * diff_id round-trips unchanged through the layer-0 slot.
         */
        size_t diff_len = strlen(diff_id);
        if (diff_len + 1 > cap) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(out, diff_id, diff_len + 1);
        return 0;
    }

    /* Li case: validate prev_chain shape too. The spec allows any
     * <algo>:<hex> digest string in the textual concatenation; in practice
     * every ChainID this helper produces is sha256-prefixed, but the
     * parser accepts both sha256 and sha512 so a future L0 sha512 diff_id
     * still composes correctly with subsequent layers.
     */
    oci_digest_algo_t prev_algo;
    char prev_hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(prev_chain, &prev_algo, prev_hex)) {
        errno = EINVAL;
        return -1;
    }

    /* Output is always sha256-prefixed: ChainID composition is defined
     * with SHA-256 in the OCI image-spec, regardless of the algorithm
     * used for the constituent digests.
     */
    static const char OUT_PREFIX[] = "sha256:";
    size_t out_need = sizeof(OUT_PREFIX) - 1 + OCI_DIGEST_SHA256_HEX_LEN + 1;
    if (cap < out_need) {
        errno = ENAMETOOLONG;
        return -1;
    }

    oci_digester_t *d = oci_digester_new(OCI_DIGEST_SHA256);
    if (!d) {
        errno = ENOMEM;
        return -1;
    }
    oci_digester_update(d, prev_chain, strlen(prev_chain));
    static const char SP = ' ';
    oci_digester_update(d, &SP, 1);
    oci_digester_update(d, diff_id, strlen(diff_id));

    memcpy(out, OUT_PREFIX, sizeof(OUT_PREFIX) - 1);
    oci_digester_finish_hex(d, out + sizeof(OUT_PREFIX) - 1);
    oci_digester_free(d);
    return 0;
}
