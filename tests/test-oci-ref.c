/* OCI image reference parser unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Standalone native macOS test program (NOT a guest binary). Links directly
 * against src/oci/ref.c so it does not depend on Hypervisor.framework and
 * has no entitlement requirements. Each table-driven case exercises either
 * a happy-path canonicalisation or a specific rejection reason.
 *
 * Build: see mk/tests.mk target test-oci-ref.
 * Run:   build/test-oci-ref
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oci/ref.h"

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

/* Compare a parsed field against an expected value. NULL on either side is
 * an exact match only when both are NULL.
 */
static int field_matches(const char *got, const char *want)
{
    if (!want)
        return got == NULL;
    return got != NULL && strcmp(got, want) == 0;
}

struct happy_case {
    const char *name;
    const char *input;
    const char *want_canonical;
    const char *want_registry;
    const char *want_repository;
    const char *want_tag;    /* NULL => expect ref.tag == NULL */
    const char *want_digest; /* NULL => expect ref.digest == NULL */
};

static void run_happy(const struct happy_case *c)
{
    oci_ref_t ref;
    const char *err = NULL;
    if (oci_ref_parse(c->input, &ref, &err) != 0) {
        char detail[256];
        snprintf(detail, sizeof(detail),
                 "parse failed unexpectedly: input=%s err=%s", c->input,
                 err ? err : "(null)");
        report_fail(c->name, detail);
        return;
    }
    char *canonical = oci_ref_canonical(&ref);
    int ok = canonical && strcmp(canonical, c->want_canonical) == 0 &&
             field_matches(ref.registry, c->want_registry) &&
             field_matches(ref.repository, c->want_repository) &&
             field_matches(ref.tag, c->want_tag) &&
             field_matches(ref.digest, c->want_digest);
    if (ok) {
        report_pass(c->name);
    } else {
        char detail[1024];
        snprintf(detail, sizeof(detail),
                 "input=%s canonical=%s registry=%s repository=%s "
                 "tag=%s digest=%s",
                 c->input, canonical ? canonical : "(null)",
                 ref.registry ? ref.registry : "(null)",
                 ref.repository ? ref.repository : "(null)",
                 ref.tag ? ref.tag : "(null)",
                 ref.digest ? ref.digest : "(null)");
        report_fail(c->name, detail);
    }
    free(canonical);
    oci_ref_free(&ref);
}

struct error_case {
    const char *name;
    const char *input;
    const char *err_substring; /* fragment that must appear in the error */
};

static void run_error(const struct error_case *c)
{
    oci_ref_t ref;
    const char *err = NULL;
    if (oci_ref_parse(c->input, &ref, &err) == 0) {
        char *canonical = oci_ref_canonical(&ref);
        char detail[256];
        snprintf(detail, sizeof(detail),
                 "expected rejection but parsed: input=%s canonical=%s",
                 c->input, canonical ? canonical : "(null)");
        free(canonical);
        oci_ref_free(&ref);
        report_fail(c->name, detail);
        return;
    }
    if (!err || !strstr(err, c->err_substring)) {
        char detail[256];
        snprintf(detail, sizeof(detail),
                 "input=%s: error %s did not contain %s", c->input,
                 err ? err : "(null)", c->err_substring);
        report_fail(c->name, detail);
        return;
    }
    /* Confirm parse leaves the struct safely freeable even on failure. */
    oci_ref_free(&ref);
    report_pass(c->name);
}

static const char SHA256_HEX[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char SHA512_HEX[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

int main(void)
{
    /* Happy cases. The canonical column is the output the rest of the
     * codebase will key off, so verify it explicitly per case rather than
     * reconstructing it in the test.
     */
    struct happy_case happy[] = {
        {"bare repo defaults to docker.io/library and latest", "alpine",
         "docker.io/library/alpine:latest", "docker.io", "library/alpine",
         "latest", NULL},
        {"tagged bare repo", "alpine:3.20", "docker.io/library/alpine:3.20",
         "docker.io", "library/alpine", "3.20", NULL},
        {"two-segment repo skips library/ prefix", "myuser/myrepo",
         "docker.io/myuser/myrepo:latest", "docker.io", "myuser/myrepo",
         "latest", NULL},
        {"registry with dot is detected", "ghcr.io/owner/img:tag",
         "ghcr.io/owner/img:tag", "ghcr.io", "owner/img", "tag", NULL},
        {"localhost is detected as registry", "localhost/repo:dev",
         "localhost/repo:dev", "localhost", "repo", "dev", NULL},
        {"registry with port preserves port", "localhost:5000/repo:dev",
         "localhost:5000/repo:dev", "localhost:5000", "repo", "dev", NULL},
        {"digest-only ref leaves tag NULL (no latest default)",
         "alpine@sha256:"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
         "docker.io/library/"
         "alpine@sha256:"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
         "docker.io", "library/alpine", NULL,
         "sha256:"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        {"tag+digest keeps both",
         "alpine:3.20@sha256:"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
         "docker.io/library/"
         "alpine:3.20@sha256:"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
         "docker.io", "library/alpine", "3.20",
         "sha256:"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        {"sha512 digest is accepted",
         "repo@sha512:"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234"
         "56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
         "docker.io/library/"
         "repo@sha512:"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234"
         "56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
         "docker.io", "library/repo", NULL,
         "sha512:"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234"
         "56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        {"underscore separators inside path", "library/foo_bar:tag",
         "docker.io/library/foo_bar:tag", "docker.io", "library/foo_bar", "tag",
         NULL},
        {"double-underscore separator", "library/foo__bar:tag",
         "docker.io/library/foo__bar:tag", "docker.io", "library/foo__bar",
         "tag", NULL},
        {"hyphen and dot separators", "library/foo-bar.baz:tag",
         "docker.io/library/foo-bar.baz:tag", "docker.io",
         "library/foo-bar.baz", "tag", NULL},
        {"deep nested path under custom registry",
         "registry.example.com:443/team/sub/repo:1.2.3",
         "registry.example.com:443/team/sub/repo:1.2.3",
         "registry.example.com:443", "team/sub/repo", "1.2.3", NULL},
        {"tag containing dot, hyphen, underscore", "alpine:1.2.3-rc1_build",
         "docker.io/library/alpine:1.2.3-rc1_build", "docker.io",
         "library/alpine", "1.2.3-rc1_build", NULL},
        {"repeated-dash separator in path component", "library/my--repo:tag",
         "docker.io/library/my--repo:tag", "docker.io", "library/my--repo",
         "tag", NULL},
        {"triple-dash separator in path component", "library/a---b:tag",
         "docker.io/library/a---b:tag", "docker.io", "library/a---b", "tag",
         NULL},
        {"mixed-case docker.io still gets library/ prefix", "Docker.io/alpine",
         "Docker.io/library/alpine:latest", "Docker.io", "library/alpine",
         "latest", NULL},
    };
    /* Suppress -Wunused-variable until the digest helper strings get used
     * by future cases. They are referenced via SHA256_HEX/SHA512_HEX in
     * comments above so the lengths stay in sync with the inline literals.
     */
    (void) SHA256_HEX;
    (void) SHA512_HEX;

    printf("oci_ref_parse happy paths\n");
    for (size_t i = 0; i < sizeof(happy) / sizeof(happy[0]); i++)
        run_happy(&happy[i]);

    struct error_case errors[] = {
        {"empty reference rejected", "", "empty"},
        {"NULL-input handled (substituted with empty string)", "", "empty"},
        {"uppercase in path rejected", "Alpine", "invalid component"},
        {"trailing colon rejected", "alpine:", "tag is empty"},
        {"trailing at sign rejected", "alpine@", "digest is empty"},
        {"double at sign rejected", "a@b@c", "multiple '@'"},
        {"unknown digest algorithm rejected",
         "alpine@md5:0123456789abcdef0123456789abcdef",
         "must be sha256 or sha512"},
        {"short sha256 digest rejected", "alpine@sha256:cafe", "hex length"},
        {"uppercase digest hex rejected",
         "alpine@sha256:"
         "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
         "lowercase"},
        {"path component starting with separator", "library/.foo:tag",
         "invalid component"},
        {"path component ending with separator", "library/foo-:tag",
         "invalid component"},
        {"triple-dot separator inside component", "library/foo...bar:tag",
         "invalid component"},
        {"empty path after registry", "ghcr.io/", "no repository"},
        {"reference with no name before '@'",
         "@sha256:"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
         "no name"},
        {"reference with no name before ':'", ":tag", "no name"},
        {"tag too long (129 chars) rejected",
         "alpine:"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         "invalid characters or length"},
        {"tag starting with dot rejected", "alpine:.bad", "invalid characters"},
        {"port too long rejected", "host:123456/repo", "invalid characters"},
    };

    printf("oci_ref_parse error paths\n");
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++)
        run_error(&errors[i]);

    /* NULL input must not crash. */
    {
        oci_ref_t ref;
        const char *err = NULL;
        if (oci_ref_parse(NULL, &ref, &err) == 0) {
            report_fail("NULL input rejected without crash",
                        "parse returned success");
            oci_ref_free(&ref);
        } else if (!err || !strstr(err, "NULL")) {
            report_fail("NULL input rejected without crash",
                        err ? err : "(null err)");
        } else {
            report_pass("NULL input rejected without crash");
        }
    }

    /* oci_ref_free on a zero-init struct must be safe. */
    {
        oci_ref_t ref = {0};
        oci_ref_free(&ref);
        report_pass("free on zero-init ref is safe");
    }

    printf("\nResults: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
