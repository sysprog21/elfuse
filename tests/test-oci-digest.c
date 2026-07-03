/* OCI digest module unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native macOS test program. Links directly against src/oci/digest.c (which
 * uses CommonCrypto). Verifies the streaming and one-shot APIs against the
 * NIST FIPS-180-4 published SHA-256 and SHA-512 vectors so any future
 * regression in the chunking or hex encoder shows up immediately.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oci/digest.h"

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

static int total = 0;
static int passed = 0;

static void report_pass(const char *name)
{
    total++;
    passed++;
    printf("  " GREEN "OK" RESET "   %s\n", name);
}

static void report_fail(const char *name, const char *detail)
{
    total++;
    printf("  " RED "FAIL" RESET " %s: %s\n", name, detail ? detail : "");
}

static void check_one_shot(const char *name,
                           oci_digest_algo_t algo,
                           const void *buf,
                           size_t len,
                           const char *want_hex)
{
    char got[OCI_DIGEST_HEX_MAX + 1];
    size_t n = oci_digest_bytes(algo, buf, len, got);
    if (n == 0) {
        report_fail(name, "oci_digest_bytes returned 0");
        return;
    }
    if (strcmp(got, want_hex) != 0) {
        char detail[512];
        snprintf(detail, sizeof(detail), "got=%s want=%s", got, want_hex);
        report_fail(name, detail);
        return;
    }
    report_pass(name);
}

static void check_streaming(const char *name,
                            oci_digest_algo_t algo,
                            const char *want_hex,
                            const void *buf,
                            size_t len,
                            size_t chunk)
{
    oci_digester_t *d = oci_digester_new(algo);
    if (!d) {
        report_fail(name, "digester_new returned NULL");
        return;
    }
    const unsigned char *p = buf;
    while (len > 0) {
        size_t step = len < chunk ? len : chunk;
        oci_digester_update(d, p, step);
        p += step;
        len -= step;
    }
    char got[OCI_DIGEST_HEX_MAX + 1];
    size_t n = oci_digester_finish_hex(d, got);
    oci_digester_free(d);
    if (n == 0) {
        report_fail(name, "finish_hex returned 0");
        return;
    }
    if (strcmp(got, want_hex) != 0) {
        char detail[512];
        snprintf(detail, sizeof(detail), "got=%s want=%s", got, want_hex);
        report_fail(name, detail);
        return;
    }
    report_pass(name);
}

/* SHA-256 of the empty string, "abc", the canonical 56-byte test vector, and
 * the standard 1 MiB 'a' marathon vector. Source: NIST FIPS 180-4 examples
 * and the test vector pages collected by NIST CAVP. Kept inline so the test
 * binary stays self-contained and offline.
 */
static const char SHA256_EMPTY[] =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
static const char SHA256_ABC[] =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
static const char SHA256_56[] =
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
static const char SHA256_MILLION_A[] =
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

static const char SHA512_EMPTY[] =
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
static const char SHA512_ABC[] =
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

static const char STR_56[] =
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

static const char VALID_SHA256_HEX[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

int main(void)
{
    printf("oci_digest one-shot vectors\n");
    check_one_shot("sha256(\"\")", OCI_DIGEST_SHA256, "", 0, SHA256_EMPTY);
    check_one_shot("sha256(\"abc\")", OCI_DIGEST_SHA256, "abc", 3, SHA256_ABC);
    check_one_shot("sha256(56-byte vector)", OCI_DIGEST_SHA256, STR_56,
                   sizeof(STR_56) - 1, SHA256_56);
    check_one_shot("sha512(\"\")", OCI_DIGEST_SHA512, "", 0, SHA512_EMPTY);
    check_one_shot("sha512(\"abc\")", OCI_DIGEST_SHA512, "abc", 3, SHA512_ABC);

    /* The 1 MiB 'a' vector verifies that the chunking loop inside
     * oci_digester_update produces the same hash as a one-shot call. Build
     * the buffer dynamically so the test source does not balloon.
     */
    printf("oci_digest streaming\n");
    const size_t million = 1000000;
    char *blob = malloc(million);
    if (!blob) {
        fprintf(stderr, "alloc million bytes failed\n");
        return 1;
    }
    memset(blob, 'a', million);
    check_one_shot("sha256(1M 'a' one-shot)", OCI_DIGEST_SHA256, blob, million,
                   SHA256_MILLION_A);
    check_streaming("sha256(1M 'a' streamed in 4 KiB chunks)",
                    OCI_DIGEST_SHA256, SHA256_MILLION_A, blob, million, 4096);
    check_streaming("sha256(1M 'a' streamed in 17-byte chunks)",
                    OCI_DIGEST_SHA256, SHA256_MILLION_A, blob, million, 17);
    free(blob);

    /* Boundary calls: NULL / zero-length updates must not crash and must not
     * corrupt the running state.
     */
    {
        oci_digester_t *d = oci_digester_new(OCI_DIGEST_SHA256);
        oci_digester_update(d, NULL, 0);
        oci_digester_update(d, "", 0);
        oci_digester_update(d, NULL, 7); /* len ignored when buf NULL */
        char got[OCI_DIGEST_HEX_MAX + 1];
        oci_digester_update(d, "abc", 3);
        oci_digester_finish_hex(d, got);
        oci_digester_free(d);
        if (strcmp(got, SHA256_ABC) == 0)
            report_pass("update tolerates NULL / zero-length");
        else
            report_fail("update tolerates NULL / zero-length", got);
    }

    printf("oci_digest_hex_valid\n");
    if (oci_digest_hex_valid(OCI_DIGEST_SHA256, VALID_SHA256_HEX))
        report_pass("accepts canonical sha256 hex");
    else
        report_fail("accepts canonical sha256 hex", NULL);

    if (!oci_digest_hex_valid(OCI_DIGEST_SHA256, NULL))
        report_pass("rejects NULL hex");
    else
        report_fail("rejects NULL hex", NULL);

    if (!oci_digest_hex_valid(
            OCI_DIGEST_SHA256,
            "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"))
        report_pass("rejects uppercase hex");
    else
        report_fail("rejects uppercase hex", NULL);

    if (!oci_digest_hex_valid(OCI_DIGEST_SHA256, "deadbeef"))
        report_pass("rejects short hex");
    else
        report_fail("rejects short hex", NULL);

    if (!oci_digest_hex_valid(
            OCI_DIGEST_SHA256,
            "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
        report_pass("rejects non-hex char");
    else
        report_fail("rejects non-hex char", NULL);

    if (!oci_digest_hex_valid(OCI_DIGEST_SHA512, VALID_SHA256_HEX))
        report_pass("rejects sha256-length hex against sha512");
    else
        report_fail("rejects sha256-length hex against sha512", NULL);

    printf("oci_digest_parse\n");
    {
        oci_digest_algo_t algo;
        char hex[OCI_DIGEST_HEX_MAX + 1];
        char input[256];
        snprintf(input, sizeof(input), "sha256:%s", VALID_SHA256_HEX);
        if (oci_digest_parse(input, &algo, hex) && algo == OCI_DIGEST_SHA256 &&
            strcmp(hex, VALID_SHA256_HEX) == 0)
            report_pass("parse sha256 form");
        else
            report_fail("parse sha256 form", hex);
    }
    {
        oci_digest_algo_t algo;
        char hex[OCI_DIGEST_HEX_MAX + 1];
        if (!oci_digest_parse("md5:deadbeef", &algo, hex))
            report_pass("parse rejects unknown algo");
        else
            report_fail("parse rejects unknown algo", NULL);
    }
    {
        oci_digest_algo_t algo;
        char hex[OCI_DIGEST_HEX_MAX + 1];
        if (!oci_digest_parse("sha256-no-colon", &algo, hex))
            report_pass("parse rejects missing colon");
        else
            report_fail("parse rejects missing colon", NULL);
    }
    {
        oci_digest_algo_t algo;
        char hex[OCI_DIGEST_HEX_MAX + 1];
        if (!oci_digest_parse("sha256:short", &algo, hex))
            report_pass("parse rejects short hex");
        else
            report_fail("parse rejects short hex", NULL);
    }
    {
        oci_digest_algo_t algo;
        char hex[OCI_DIGEST_HEX_MAX + 1];
        char buf[256];
        snprintf(buf, sizeof(buf), "sha256:%s",
                 "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789a"
                 "bcdef");
        if (!oci_digest_parse(buf, &algo, hex))
            report_pass("parse rejects uppercase hex");
        else
            report_fail("parse rejects uppercase hex", NULL);
    }
    {
        oci_digest_algo_t algo;
        char hex[OCI_DIGEST_HEX_MAX + 1];
        if (!oci_digest_parse(NULL, &algo, hex))
            report_pass("parse rejects NULL input");
        else
            report_fail("parse rejects NULL input", NULL);
    }

    /* Algo name lookups stay in sync with the enum values. */
    if (oci_digest_algo_name(OCI_DIGEST_SHA256) &&
        strcmp(oci_digest_algo_name(OCI_DIGEST_SHA256), "sha256") == 0)
        report_pass("algo_name maps sha256");
    else
        report_fail("algo_name maps sha256", NULL);

    if (oci_digest_algo_name(OCI_DIGEST_SHA512) &&
        strcmp(oci_digest_algo_name(OCI_DIGEST_SHA512), "sha512") == 0)
        report_pass("algo_name maps sha512");
    else
        report_fail("algo_name maps sha512", NULL);

    if (oci_digest_hex_len(OCI_DIGEST_SHA256) == OCI_DIGEST_SHA256_HEX_LEN &&
        oci_digest_hex_len(OCI_DIGEST_SHA512) == OCI_DIGEST_SHA512_HEX_LEN)
        report_pass("hex_len matches public constants");
    else
        report_fail("hex_len matches public constants", NULL);

    {
        oci_digest_algo_t algo;
        if (oci_digest_algo_from_name("sha256", &algo) &&
            algo == OCI_DIGEST_SHA256 &&
            oci_digest_algo_from_name("sha512", &algo) &&
            algo == OCI_DIGEST_SHA512 &&
            !oci_digest_algo_from_name("sha1", &algo) &&
            !oci_digest_algo_from_name(NULL, &algo))
            report_pass("algo_from_name accepts known and rejects unknown");
        else
            report_fail("algo_from_name accepts known and rejects unknown",
                        NULL);
    }

    /* --- ChainID --------------------------------------------------------
     *
     * OCI image-spec v1.0.2 section 3.4: ChainID(L0) == DiffID(L0), and
     * ChainID(Li) == SHA-256("<prev_chain> <diff_id>"). The Li tests
     * recompute the expected value via the same digester library used by
     * the helper rather than hard-coding a magic hex string, so the test
     * stays sensitive to drift in the input encoding (e.g. accidentally
     * dropping the space, swapping argument order, or hashing only the
     * hex portion instead of the full "<algo>:<hex>" digest).
     */
    printf("oci_chainid_compute\n");

    static const char DIFF_A[] =
        "sha256:"
        "1111111111111111111111111111111111111111111111111111111111111111";
    static const char DIFF_B[] =
        "sha256:"
        "2222222222222222222222222222222222222222222222222222222222222222";
    static const char DIFF_512[] =
        "sha512:"
        "3333333333333333333333333333333333333333333333333333333333333333"
        "3333333333333333333333333333333333333333333333333333333333333333";

    {
        /* L0 case: helper copies diff_id verbatim, regardless of algo. */
        char out[OCI_DIGEST_HEX_MAX + 16];
        if (oci_chainid_compute(NULL, DIFF_A, out, sizeof(out)) != 0) {
            report_fail("chainid L0 sha256 passthrough", "rc != 0");
        } else if (strcmp(out, DIFF_A) != 0) {
            report_fail("chainid L0 sha256 passthrough", out);
        } else {
            report_pass("chainid L0 sha256 passthrough");
        }
        if (oci_chainid_compute(NULL, DIFF_512, out, sizeof(out)) != 0) {
            report_fail("chainid L0 sha512 passthrough", "rc != 0");
        } else if (strcmp(out, DIFF_512) != 0) {
            report_fail("chainid L0 sha512 passthrough", out);
        } else {
            report_pass("chainid L0 sha512 passthrough");
        }
    }

    {
        /* Li case: helper hashes prev + " " + diff. Independently compute
         * the expected hash here so the test catches off-by-one mistakes
         * (e.g. trailing NUL leaking into the hash, missing space).
         */
        char want_hex[OCI_DIGEST_HEX_MAX + 1];
        char concat[256];
        snprintf(concat, sizeof(concat), "%s %s", DIFF_A, DIFF_B);
        oci_digest_bytes(OCI_DIGEST_SHA256, concat, strlen(concat), want_hex);
        char want[OCI_DIGEST_HEX_MAX + 16];
        snprintf(want, sizeof(want), "sha256:%s", want_hex);

        char got[OCI_DIGEST_HEX_MAX + 16];
        if (oci_chainid_compute(DIFF_A, DIFF_B, got, sizeof(got)) != 0) {
            report_fail("chainid Li matches OCI spec composition", "rc != 0");
        } else if (strcmp(got, want) != 0) {
            char detail[1024];
            snprintf(detail, sizeof(detail), "got=%s want=%s", got, want);
            report_fail("chainid Li matches OCI spec composition", detail);
        } else {
            report_pass("chainid Li matches OCI spec composition");
        }
    }

    {
        /* Chain three layers and confirm the helper composes left-to-right
         * (the iteration order any caller uses).
         */
        char chain0[OCI_DIGEST_HEX_MAX + 16];
        char chain1[OCI_DIGEST_HEX_MAX + 16];
        char chain2[OCI_DIGEST_HEX_MAX + 16];
        if (oci_chainid_compute(NULL, DIFF_A, chain0, sizeof(chain0)) != 0 ||
            oci_chainid_compute(chain0, DIFF_B, chain1, sizeof(chain1)) != 0 ||
            oci_chainid_compute(chain1, DIFF_A, chain2, sizeof(chain2)) != 0) {
            report_fail("chainid three-layer chain composes", "rc != 0");
        } else if (strncmp(chain1, "sha256:", 7) != 0 ||
                   strncmp(chain2, "sha256:", 7) != 0) {
            report_fail("chainid three-layer chain composes",
                        "non-sha256 prefix");
        } else if (strcmp(chain1, chain2) == 0) {
            /* The two Li hashes consume different prev_chain values, so
             * they cannot collide unless the helper ignored prev_chain.
             */
            report_fail("chainid three-layer chain composes",
                        "chain1 == chain2 (prev_chain ignored?)");
        } else {
            report_pass("chainid three-layer chain composes");
        }
    }

    {
        /* Output buffer too small => ENAMETOOLONG, no write past cap. */
        char small[8];
        memset(small, 'X', sizeof(small));
        errno = 0;
        int rc = oci_chainid_compute(DIFF_A, DIFF_B, small, sizeof(small));
        if (rc != -1 || errno != ENAMETOOLONG) {
            char detail[64];
            snprintf(detail, sizeof(detail), "rc=%d errno=%d", rc, errno);
            report_fail("chainid rejects small cap with ENAMETOOLONG", detail);
        } else {
            report_pass("chainid rejects small cap with ENAMETOOLONG");
        }
    }

    {
        /* Malformed diff_id => EINVAL. */
        char out[OCI_DIGEST_HEX_MAX + 16];
        errno = 0;
        if (oci_chainid_compute(DIFF_A, "not-a-digest", out, sizeof(out)) !=
                -1 ||
            errno != EINVAL) {
            report_fail("chainid rejects malformed diff_id", "wrong errno");
        } else {
            report_pass("chainid rejects malformed diff_id");
        }
        errno = 0;
        if (oci_chainid_compute("not-a-digest", DIFF_B, out, sizeof(out)) !=
                -1 ||
            errno != EINVAL) {
            report_fail("chainid rejects malformed prev_chain", "wrong errno");
        } else {
            report_pass("chainid rejects malformed prev_chain");
        }
        errno = 0;
        if (oci_chainid_compute(DIFF_A, NULL, out, sizeof(out)) != -1 ||
            errno != EINVAL) {
            report_fail("chainid rejects NULL diff_id", "wrong errno");
        } else {
            report_pass("chainid rejects NULL diff_id");
        }
    }

    printf("\nResults: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
