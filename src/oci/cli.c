/* `elfuse oci` subcommand dispatch
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * pull shells out to skopeo (see pull.h) and pins the copied digest;
 * inspect renders the local manifest tree offline (src/oci/inspect.c);
 * unpack / clone / run / prune / rebuild-cache / status operate purely
 * on the local store and sysroot volume. list still returns rc=2 "not
 * implemented yet".
 */

#include "cli.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "clone-rootfs.h"
#include "inspect.h"
#include "pull.h"
#include "rebuild-cache.h"
#include "ref.h"
#include "run.h"
#include "status.h"
#include "store.h"
#include "unpack.h"
#include "volume.h"

/* Set once on entry to oci_cli_main, before any usage text can print. Holds
 * "elfuse oci" for the subcommand spelling or the multicall basename (e.g.
 * "elfuse-container") so help output always echoes the invocation the user
 * actually typed.
 */
static const char *cli_name = "elfuse oci";

const char *oci_cli_name(void)
{
    return cli_name;
}

static int print_usage(FILE *out)
{
    fprintf(out, "usage: %s <subcommand> [args]\n", cli_name);
    fputs(
        "\n"
        "Subcommands:\n"
        "  pull    [OPTIONS] <ref>  Download an image into the local store\n"
        "  inspect [OPTIONS] <ref>  Show the canonical reference and parsed "
        "fields\n"
        "  unpack  [OPTIONS] <ref>  Apply layers into a case-sensitive "
        "sysroot\n"
        "  clone   [OPTIONS] <ref>  Create a per-run rootfs via APFS "
        "clonefile\n"
        "  run     [OPTIONS] <ref> [ARG...]\n"
        "                           Launch a guest binary from a pulled image\n"
        "  prune                    Remove unreferenced blobs from the local "
        "store\n"
        "  rebuild-cache            Back-fill stack cache from unpacked "
        "sysroots\n"
        "  status                   Report pins, unpacked sysroots, and cache "
        "totals\n"
        "  list                     List images in the local store\n"
        "\n"
        "Pull options:\n"
        "  --store DIR           Override the local store root\n"
        "                        (default: ~/Library/Application "
        "Support/elfuse/store)\n"
        "  --arch ARCH           Resolve multi-arch refs to ARCH\n"
        "                        (default: arm64; use amd64 for Rosetta)\n"
        "  -q, --quiet           Suppress skopeo progress output\n"
        "\n"
        "Pull transfers via skopeo(1): registry auth uses `skopeo login`\n"
        "or docker credential helpers; TLS and mirror policy follow\n"
        "containers-policy.json(5) and containers-registries.conf(5).\n"
        "\n"
        "Inspect options:\n"
        "  --store DIR           Override the local store root\n"
        "  --volume DIR          Include unpacked sysroots under DIR/images/\n"
        "                        in the layer reuse comparison\n"
        "  --all-platforms       List every platform entry of an image index\n"
        "                        instead of drilling into linux/arm64\n"
        "\n"
        "Unpack options:\n"
        "  --store DIR           Override the local store root\n"
        "  --volume DIR          Override the sysroot APFS volume mount point\n"
        "                        (default: auto-provisioned sparsebundle "
        "under\n"
        "                         ~/Library/Application "
        "Support/elfuse/sysroots/)\n"
        "  --force               Re-extract even if the image sysroot exists\n"
        "  -q, --quiet           Suppress per-layer progress output\n"
        "\n"
        "Clone options:\n"
        "  --store DIR           Override the local store root\n"
        "  --volume DIR          Override the sysroot APFS volume mount point\n"
        "  --name NAME           Human-friendly suffix for the per-run rootfs\n"
        "  --keep                Do not register the run dir for cleanup "
        "(no-op)\n"
        "\n"
        "Prune options:\n"
        "  --store DIR           Override the local store root\n"
        "  --volume DIR          Treat unpacked sysroots under DIR/images/ as "
        "roots\n"
        "  --commit              Actually unlink dangling blobs "
        "(default: dry-run)\n"
        "  --older-than DUR      Skip dangling blobs younger than DUR\n"
        "                        (suffixes: s, m, h, d, w; plain integer = "
        "seconds;\n"
        "                         0 = no filter)\n"
        "  --keep-bytes SIZE     Keep up to SIZE bytes of newest dangling "
        "blobs;\n"
        "                        (suffixes: K, M, G; KiB-based; 0 = no "
        "budget)\n"
        "\n"
        "Rebuild-cache options:\n"
        "  --store DIR           Override the local store root\n"
        "  --volume DIR          Override the sysroot APFS volume mount point\n"
        "  --commit              Actually write stack snapshots "
        "(default: dry-run)\n"
        "\n"
        "Status options:\n"
        "  --store DIR           Override the local store root\n"
        "  --volume DIR          Include unpacked sysroots under DIR/images/\n"
        "                        in the report\n"
        "  --json                Emit machine-readable JSON (schemaVersion 1)\n"
        "  --no-disk-usage       Skip recursive size sums (faster on large "
        "stores)\n"
        "\n"
        "Refs follow the docker/containerd grammar:\n"
        "  alpine, alpine:3.20, user/repo, ghcr.io/owner/img:tag,\n"
        "  repo@sha256:<hex>, repo:tag@sha256:<hex>\n",
        out);
    return out == stderr ? 2 : 0;
}

/* Argument parser state for `oci inspect`. Mirrors pull_args_t in shape so a
 * future cleanup could share the flag-loop, but the option set is disjoint
 * enough that today the two parsers live side by side.
 */
typedef struct {
    const char *store_root;
    const char *volume_root;
    bool show_all_platforms;
    const char *ref_str;
} inspect_args_t;

static int parse_inspect_args(int argc, char **argv, inspect_args_t *out)
{
    int i = 1;
    while (i < argc) {
        const char *a = argv[i];
        if (a[0] != '-')
            break;
        if (!strcmp(a, "--")) {
            i++;
            break;
        }
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            return 1;
        } else if (!strcmp(a, "--all-platforms")) {
            out->show_all_platforms = true;
        } else if (!strcmp(a, "--store")) {
            if (++i >= argc) {
                fputs("error: --store needs an argument\n", stderr);
                return -1;
            }
            out->store_root = argv[i];
        } else if (!strcmp(a, "--volume")) {
            if (++i >= argc) {
                fputs("error: --volume needs an argument\n", stderr);
                return -1;
            }
            out->volume_root = argv[i];
        } else {
            fprintf(stderr, "error: unknown inspect option: %s\n", a);
            return -1;
        }
        i++;
    }
    if (i >= argc) {
        fputs("error: inspect needs a reference argument\n", stderr);
        return -1;
    }
    if (i != argc - 1) {
        fputs("error: extra arguments after inspect reference\n", stderr);
        return -1;
    }
    out->ref_str = argv[i];
    return 0;
}

static int cmd_inspect(int argc, char **argv)
{
    inspect_args_t args = {0};
    int prc = parse_inspect_args(argc, argv, &args);
    if (prc == 1)
        return print_usage(stdout);
    if (prc < 0)
        return 2;

    oci_ref_t ref = {0};
    const char *err = NULL;
    if (oci_ref_parse(args.ref_str, &ref, &err) < 0) {
        fprintf(stderr, "error: %s\n", err ? err : "invalid reference");
        return 1;
    }
    char *canonical = oci_ref_canonical(&ref);
    if (!canonical) {
        fputs("error: out of memory rendering canonical reference\n", stderr);
        oci_ref_free(&ref);
        return 1;
    }
    printf("canonical:  %s\n", canonical);
    printf("registry:   %s\n", ref.registry);
    printf("repository: %s\n", ref.repository);
    printf("tag:        %s\n", ref.tag ? ref.tag : "(none)");
    printf("digest:     %s\n", ref.digest ? ref.digest : "(none)");
    free(canonical);

    /* Resolve store root: --store override or platform default. */
    char *default_root = NULL;
    const char *store_root = args.store_root;
    if (!store_root) {
        default_root = oci_store_default_root();
        if (!default_root) {
            fprintf(stderr,
                    "error: could not determine default store root "
                    "(HOME not set?)\n");
            oci_ref_free(&ref);
            return 1;
        }
        store_root = default_root;
    }

    oci_store_t *store = oci_store_open(store_root);
    if (!store) {
        fprintf(stderr, "error: could not open store at %s: %s\n", store_root,
                strerror(errno));
        oci_ref_free(&ref);
        free(default_root);
        return 1;
    }

    oci_inspect_options_t opts = {
        .out = stdout,
        .show_all_platforms = args.show_all_platforms,
        .volume_root = args.volume_root,
    };
    err = NULL;
    int rc = oci_inspect(store, &ref, &opts, &err);
    if (rc < 0 && err)
        fprintf(stderr, "error: %s\n", err);

    oci_store_close(store);
    oci_ref_free(&ref);
    free(default_root);
    return rc < 0 ? 1 : 0;
}

/* Argument parser state for `oci pull`. Defaults are populated by the caller,
 * then patched by parse_pull_args.
 */
typedef struct {
    const char *store_root; /* heap-owned by main, not by parse */
    const char *arch;
    bool quiet;
    const char *ref_str;
} pull_args_t;

/* argv layout coming in: ["pull", "--flag", "...", "<ref>"]. argv[0] is the
 * subcommand name; argv[argc-1] is the ref. Anything in between is options.
 * Returns 0 on success, -1 on bad arguments (after printing an error).
 */
static int parse_pull_args(int argc, char **argv, pull_args_t *out)
{
    int i = 1;
    while (i < argc) {
        const char *a = argv[i];
        if (a[0] != '-')
            break;
        if (!strcmp(a, "--")) {
            i++;
            break;
        }
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            return 1;
        } else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
            out->quiet = true;
        } else if (!strcmp(a, "--store")) {
            if (++i >= argc) {
                fputs("error: --store needs an argument\n", stderr);
                return -1;
            }
            out->store_root = argv[i];
        } else if (!strcmp(a, "--arch")) {
            if (++i >= argc) {
                fputs("error: --arch needs an argument\n", stderr);
                return -1;
            }
            out->arch = argv[i];
        } else {
            fprintf(stderr, "error: unknown pull option: %s\n", a);
            return -1;
        }
        i++;
    }
    if (i >= argc) {
        fputs("error: pull needs a reference argument\n", stderr);
        return -1;
    }
    if (i != argc - 1) {
        fputs("error: extra arguments after pull reference\n", stderr);
        return -1;
    }
    out->ref_str = argv[i];
    return 0;
}

static int cmd_pull(int argc, char **argv)
{
    pull_args_t args = {0};
    int prc = parse_pull_args(argc, argv, &args);
    if (prc == 1)
        return print_usage(stdout);
    if (prc < 0)
        return 2;

    /* Default store root: either --store override or the platform default. */
    char *default_root = NULL;
    const char *store_root = args.store_root;
    if (!store_root) {
        default_root = oci_store_default_root();
        if (!default_root) {
            fprintf(stderr,
                    "error: could not determine default store root "
                    "(HOME not set?)\n");
            return 1;
        }
        store_root = default_root;
    }

    oci_ref_t ref = {0};
    const char *err = NULL;
    if (oci_ref_parse(args.ref_str, &ref, &err) < 0) {
        fprintf(stderr, "error: invalid reference: %s\n",
                err ? err : "(unknown)");
        free(default_root);
        return 1;
    }

    /* Opening the store first guarantees the oci-layout marker and
     * index.json exist before skopeo writes into the directory.
     */
    oci_store_t *store = oci_store_open(store_root);
    if (!store) {
        fprintf(stderr, "error: could not open store at %s: %s\n", store_root,
                strerror(errno));
        oci_ref_free(&ref);
        free(default_root);
        return 1;
    }

    if (!args.quiet) {
        char *canon = oci_ref_canonical(&ref);
        fprintf(stderr, "elfuse oci pull %s\n  store: %s\n",
                canon ? canon : args.ref_str, store_root);
        free(canon);
    }

    oci_pull_options_t popts = {
        .quiet = args.quiet,
        .arch = args.arch,
    };
    err = NULL;
    int rc = oci_pull(store, store_root, &ref, &popts, &err);
    if (rc < 0) {
        fprintf(stderr, "error: pull failed: %s\n",
                err ? err : strerror(errno));
    } else if (!args.quiet) {
        fputs("done.\n", stderr);
    }

    oci_store_close(store);
    oci_ref_free(&ref);
    free(default_root);
    return rc < 0 ? 1 : 0;
}

typedef struct {
    const char *store_root;
    const char *volume_root;
    const char *ref_str;
    const char *name; /* clone only */
    bool quiet;
    bool force_relayer;
    bool keep_on_exit; /* clone only */
} unpack_args_t;

static int parse_unpack_args(int argc,
                             char **argv,
                             unpack_args_t *out,
                             bool clone_mode)
{
    int i = 1;
    while (i < argc) {
        const char *a = argv[i];
        if (a[0] != '-')
            break;
        if (!strcmp(a, "--")) {
            i++;
            break;
        }
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            return 1;
        } else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
            out->quiet = true;
        } else if (!strcmp(a, "--force")) {
            if (clone_mode) {
                fputs("error: --force is not valid for oci clone\n", stderr);
                return -1;
            }
            out->force_relayer = true;
        } else if (!strcmp(a, "--keep")) {
            if (!clone_mode) {
                fputs("error: --keep is only valid for oci clone\n", stderr);
                return -1;
            }
            out->keep_on_exit = true;
        } else if (!strcmp(a, "--store")) {
            if (++i >= argc) {
                fputs("error: --store needs an argument\n", stderr);
                return -1;
            }
            out->store_root = argv[i];
        } else if (!strcmp(a, "--volume")) {
            if (++i >= argc) {
                fputs("error: --volume needs an argument\n", stderr);
                return -1;
            }
            out->volume_root = argv[i];
        } else if (clone_mode && !strcmp(a, "--name")) {
            if (++i >= argc) {
                fputs("error: --name needs an argument\n", stderr);
                return -1;
            }
            out->name = argv[i];
        } else {
            fprintf(stderr, "error: unknown option: %s\n", a);
            return -1;
        }
        i++;
    }
    if (i >= argc) {
        fputs("error: subcommand needs a reference argument\n", stderr);
        return -1;
    }
    if (i != argc - 1) {
        fputs("error: extra arguments after reference\n", stderr);
        return -1;
    }
    out->ref_str = argv[i];
    return 0;
}

static int do_unpack(const unpack_args_t *args,
                     char **out_image_dir,
                     oci_store_t **out_store_keep)
{
    char *default_root = NULL;
    const char *store_root = args->store_root;
    if (!store_root) {
        default_root = oci_store_default_root();
        if (!default_root) {
            fprintf(stderr,
                    "error: could not determine default store root (HOME?)\n");
            return 1;
        }
        store_root = default_root;
    }

    oci_ref_t ref = {0};
    const char *err = NULL;
    if (oci_ref_parse(args->ref_str, &ref, &err) < 0) {
        fprintf(stderr, "error: invalid reference: %s\n",
                err ? err : "(unknown)");
        free(default_root);
        return 1;
    }

    oci_store_t *store = oci_store_open(store_root);
    if (!store) {
        fprintf(stderr, "error: could not open store at %s: %s\n", store_root,
                strerror(errno));
        oci_ref_free(&ref);
        free(default_root);
        return 1;
    }

    oci_unpack_options_t uopts = {
        .volume_root = args->volume_root,
        .quiet = args->quiet,
        .force_relayer = args->force_relayer,
    };
    err = NULL;
    int rc = oci_unpack(store, &ref, &uopts, out_image_dir, &err);
    if (rc < 0) {
        fprintf(stderr, "error: unpack failed: %s\n",
                err ? err : strerror(errno));
        oci_store_close(store);
        oci_ref_free(&ref);
        free(default_root);
        return 1;
    }
    oci_ref_free(&ref);
    free(default_root);
    if (out_store_keep)
        *out_store_keep = store;
    else
        oci_store_close(store);
    return 0;
}

static int cmd_unpack(int argc, char **argv)
{
    unpack_args_t args = {0};
    int prc = parse_unpack_args(argc, argv, &args, false);
    if (prc == 1)
        return print_usage(stdout);
    if (prc < 0)
        return 2;
    char *image_dir = NULL;
    int rc = do_unpack(&args, &image_dir, NULL);
    if (rc != 0) {
        free(image_dir);
        return rc;
    }
    /* stdout: just the absolute path so $(elfuse oci unpack ref) composes. */
    printf("%s\n", image_dir);
    free(image_dir);
    return 0;
}

static int cmd_clone(int argc, char **argv)
{
    unpack_args_t args = {0};
    int prc = parse_unpack_args(argc, argv, &args, true);
    if (prc == 1)
        return print_usage(stdout);
    if (prc < 0)
        return 2;

    char *image_dir = NULL;
    oci_store_t *store = NULL;
    int rc = do_unpack(&args, &image_dir, &store);
    if (rc != 0) {
        free(image_dir);
        return rc;
    }
    oci_store_close(store);

    /* Resolve the volume root the same way unpack did so clone-rootfs
     * lands in the same sparsebundle.
     */
    char *volume_root = NULL;
    const char *err = NULL;
    if (oci_volume_ensure(args.volume_root, &volume_root, &err) < 0) {
        fprintf(stderr, "error: volume_ensure failed: %s\n",
                err ? err : strerror(errno));
        free(image_dir);
        return 1;
    }

    /* image_dir has a trailing slash; strip it for the clone source. */
    size_t il = strlen(image_dir);
    if (il > 1 && image_dir[il - 1] == '/')
        image_dir[il - 1] = '\0';

    char *run_dir = NULL;
    err = NULL;
    if (oci_clone_rootfs(image_dir, volume_root, &run_dir, &err) < 0) {
        fprintf(stderr, "error: clone failed: %s\n",
                err ? err : strerror(errno));
        free(image_dir);
        free(volume_root);
        return 1;
    }
    /* --keep is forward-looking; run dirs are not auto-cleaned either way. */
    (void) args.keep_on_exit;
    printf("%s\n", run_dir);
    free(run_dir);
    free(image_dir);
    free(volume_root);
    return 0;
}

static int cmd_not_implemented(const char *name)
{
    fprintf(stderr, "error: 'oci %s' is not implemented yet (see issue #31)\n",
            name);
    return 2;
}

/* Argument parser state for `oci prune`. The flag set is intentionally
 * minimal: dry-run is the default (so the operator can review what would
 * be reclaimed before committing) and --commit is the only switch that
 * actually unlinks. --volume mirrors the same flag in unpack/clone so
 * the same volume root the user uses for unpacked sysroots also feeds
 * the keep-set walk; without --volume only pins contribute.
 *
 * older_than_sec / keep_bytes default to 0, which the store API
 * interprets as "no filter" so an operator that does not opt in sees
 * every dangling blob pruned. The CLI does not distinguish between
 * "not specified" and "--older-than 0" / "--keep-bytes 0" because
 * both compose to the same zero-filter behaviour; `oci status
 * --json` surfaces filter state from the rendered options struct
 * directly.
 */
typedef struct {
    const char *store_root;
    const char *volume_root;
    bool commit;
    uint64_t older_than_sec;
    uint64_t keep_bytes;
} prune_args_t;

/* Parse a duration string into seconds. Accepted shapes are
 *   <n>            pure integer interpreted as seconds
 *   <n>s           seconds
 *   <n>m           minutes (60s)
 *   <n>h           hours   (3600s)
 *   <n>d           days    (86400s)
 *   <n>w           weeks   (604800s)
 * where <n> is a decimal unsigned integer with no sign character. The
 * trailing suffix, when present, is a single ASCII letter; any other
 * trailing bytes are rejected. Overflow is detected by checking the
 * intermediate product against UINT64_MAX before applying it. Returns
 * 0 on success with the value written to *out; -1 on any parse or
 * overflow failure with errno=EINVAL.
 */
static int parse_duration(const char *s, uint64_t *out)
{
    if (!s || !*s) {
        errno = EINVAL;
        return -1;
    }
    /* strtoull silently accepts a leading '-' and wraps the result;
     * detect a negative sign and the leading-whitespace skip
     * explicitly so a user-facing flag never quietly parses "-5d" as
     * a huge positive duration.
     */
    if (*s == '-' || *s == '+' || *s == ' ' || *s == '\t') {
        errno = EINVAL;
        return -1;
    }
    char *endp = NULL;
    errno = 0;
    unsigned long long raw = strtoull(s, &endp, 10);
    if (errno == ERANGE) {
        errno = EINVAL;
        return -1;
    }
    if (!endp || endp == s) {
        errno = EINVAL;
        return -1;
    }
    uint64_t value = (uint64_t) raw;
    uint64_t multiplier = 1;
    if (*endp != '\0') {
        if (endp[1] != '\0') {
            errno = EINVAL;
            return -1;
        }
        switch (*endp) {
        case 's':
            multiplier = 1;
            break;
        case 'm':
            multiplier = 60;
            break;
        case 'h':
            multiplier = 3600;
            break;
        case 'd':
            multiplier = 86400;
            break;
        case 'w':
            multiplier = 604800;
            break;
        default:
            errno = EINVAL;
            return -1;
        }
    }
    if (multiplier != 0 && value > UINT64_MAX / multiplier) {
        errno = EINVAL;
        return -1;
    }
    *out = value * multiplier;
    return 0;
}

/* Parse a byte-size string into bytes. Accepted shapes are
 *   <n>            pure integer interpreted as bytes
 *   <n>K / <n>KB   1024 bytes per unit
 *   <n>M / <n>MB   1024 * 1024 bytes per unit
 *   <n>G / <n>GB   1024 * 1024 * 1024 bytes per unit
 * matching du / df conventions (KiB-based, not decimal). The
 * trailing suffix is at most two letters, case-sensitive, and the
 * second letter when present must be 'B'. Negative inputs and
 * arithmetic overflow are rejected with EINVAL; on success returns 0
 * and stores the byte count in *out.
 */
static int parse_byte_size(const char *s, uint64_t *out)
{
    if (!s || !*s) {
        errno = EINVAL;
        return -1;
    }
    if (*s == '-' || *s == '+' || *s == ' ' || *s == '\t') {
        errno = EINVAL;
        return -1;
    }
    char *endp = NULL;
    errno = 0;
    unsigned long long raw = strtoull(s, &endp, 10);
    if (errno == ERANGE) {
        errno = EINVAL;
        return -1;
    }
    if (!endp || endp == s) {
        errno = EINVAL;
        return -1;
    }
    uint64_t value = (uint64_t) raw;
    uint64_t multiplier = 1;
    if (*endp != '\0') {
        char unit = *endp;
        char trailer = endp[1];
        if (trailer != '\0' && (trailer != 'B' || endp[2] != '\0')) {
            errno = EINVAL;
            return -1;
        }
        switch (unit) {
        case 'K':
            multiplier = 1024ULL;
            break;
        case 'M':
            multiplier = 1024ULL * 1024ULL;
            break;
        case 'G':
            multiplier = 1024ULL * 1024ULL * 1024ULL;
            break;
        default:
            errno = EINVAL;
            return -1;
        }
    }
    if (multiplier != 0 && value > UINT64_MAX / multiplier) {
        errno = EINVAL;
        return -1;
    }
    *out = value * multiplier;
    return 0;
}

static int parse_prune_args(int argc, char **argv, prune_args_t *out)
{
    int i = 1;
    while (i < argc) {
        const char *a = argv[i];
        if (a[0] != '-')
            break;
        if (!strcmp(a, "--")) {
            i++;
            break;
        }
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            return 1;
        } else if (!strcmp(a, "--commit")) {
            out->commit = true;
        } else if (!strcmp(a, "--store")) {
            if (++i >= argc) {
                fputs("error: --store needs an argument\n", stderr);
                return -1;
            }
            out->store_root = argv[i];
        } else if (!strcmp(a, "--volume")) {
            if (++i >= argc) {
                fputs("error: --volume needs an argument\n", stderr);
                return -1;
            }
            out->volume_root = argv[i];
        } else if (!strcmp(a, "--older-than")) {
            if (++i >= argc) {
                fputs("error: --older-than needs an argument\n", stderr);
                return -1;
            }
            if (parse_duration(argv[i], &out->older_than_sec) < 0) {
                fprintf(stderr, "error: --older-than: invalid duration '%s'\n",
                        argv[i]);
                return -1;
            }
        } else if (!strcmp(a, "--keep-bytes")) {
            if (++i >= argc) {
                fputs("error: --keep-bytes needs an argument\n", stderr);
                return -1;
            }
            if (parse_byte_size(argv[i], &out->keep_bytes) < 0) {
                fprintf(stderr, "error: --keep-bytes: invalid byte size '%s'\n",
                        argv[i]);
                return -1;
            }
        } else {
            fprintf(stderr, "error: unknown prune option: %s\n", a);
            return -1;
        }
        i++;
    }
    if (i != argc) {
        fputs("error: prune takes no positional arguments\n", stderr);
        return -1;
    }
    return 0;
}

static int cmd_prune(int argc, char **argv)
{
    prune_args_t args = {0};
    int prc = parse_prune_args(argc, argv, &args);
    if (prc == 1)
        return print_usage(stdout);
    if (prc < 0)
        return 2;

    char *default_root = NULL;
    const char *store_root = args.store_root;
    if (!store_root) {
        default_root = oci_store_default_root();
        if (!default_root) {
            fprintf(stderr,
                    "error: could not determine default store root "
                    "(HOME not set?)\n");
            return 1;
        }
        store_root = default_root;
    }

    oci_store_t *store = oci_store_open(store_root);
    if (!store) {
        fprintf(stderr, "error: could not open store at %s: %s\n", store_root,
                strerror(errno));
        free(default_root);
        return 1;
    }

    oci_store_prune_options_t opts = {
        .commit = args.commit,
        .volume_root = args.volume_root,
        .older_than_sec = args.older_than_sec,
        .keep_bytes = args.keep_bytes,
    };
    const char *err = NULL;
    int rc = oci_store_prune(store, &opts, &err);
    if (rc < 0) {
        fprintf(stderr, "error: prune failed: %s\n",
                err ? err : strerror(errno));
        oci_store_close(store);
        free(default_root);
        return 1;
    }

    /* Output preserves the original prune line shape so existing operator
     * scripts and the compat smoke continue to match on "reclaimable: N blobs"
     * / "reclaimed: N blobs" / "kept: M blobs" / "dry-run". The new layer and
     * stack lines only render when their counter is non-zero so a single-family
     * cache still produces the legacy two-line output.
     */
    const char *verb_done = args.commit ? "reclaimed" : "reclaimable";
    const char *verb_pre = args.commit ? "reclaimed" : "reclaimable";
    if (args.commit) {
        printf("reclaimed: %zu blobs (%llu bytes)\n", opts.pruned_blobs,
               (unsigned long long) opts.pruned_bytes);
        if (opts.pruned_layers > 0)
            printf("layers:    %zu %s (%llu bytes)\n", opts.pruned_layers,
                   verb_done, (unsigned long long) opts.pruned_layer_bytes);
        if (opts.pruned_stacks > 0)
            printf("stacks:    %zu %s (%llu bytes)\n", opts.pruned_stacks,
                   verb_done, (unsigned long long) opts.pruned_stack_bytes);
        if (opts.skipped_blobs > 0)
            printf("skipped:   %zu blobs (%llu bytes)\n", opts.skipped_blobs,
                   (unsigned long long) opts.skipped_bytes);
        if (opts.skipped_layers > 0)
            printf("layers:    %zu skipped (%llu bytes)\n", opts.skipped_layers,
                   (unsigned long long) opts.skipped_layer_bytes);
        if (opts.skipped_stacks > 0)
            printf("stacks:    %zu skipped (%llu bytes)\n", opts.skipped_stacks,
                   (unsigned long long) opts.skipped_stack_bytes);
        printf("kept:      %zu blobs\n", opts.kept_blobs);
        if (opts.kept_layers > 0)
            printf("kept:      %zu layers\n", opts.kept_layers);
        if (opts.kept_stacks > 0)
            printf("kept:      %zu stacks\n", opts.kept_stacks);
    } else {
        printf("reclaimable: %zu blobs (%llu bytes)\n", opts.pruned_blobs,
               (unsigned long long) opts.pruned_bytes);
        if (opts.pruned_layers > 0)
            printf("layers:      %zu %s (%llu bytes)\n", opts.pruned_layers,
                   verb_pre, (unsigned long long) opts.pruned_layer_bytes);
        if (opts.pruned_stacks > 0)
            printf("stacks:      %zu %s (%llu bytes)\n", opts.pruned_stacks,
                   verb_pre, (unsigned long long) opts.pruned_stack_bytes);
        if (opts.skipped_blobs > 0)
            printf("skipped:     %zu blobs (%llu bytes)\n", opts.skipped_blobs,
                   (unsigned long long) opts.skipped_bytes);
        if (opts.skipped_layers > 0)
            printf("layers:      %zu skipped (%llu bytes)\n",
                   opts.skipped_layers,
                   (unsigned long long) opts.skipped_layer_bytes);
        if (opts.skipped_stacks > 0)
            printf("stacks:      %zu skipped (%llu bytes)\n",
                   opts.skipped_stacks,
                   (unsigned long long) opts.skipped_stack_bytes);
        printf("kept:        %zu blobs\n", opts.kept_blobs);
        if (opts.kept_layers > 0)
            printf("kept:        %zu layers\n", opts.kept_layers);
        if (opts.kept_stacks > 0)
            printf("kept:        %zu stacks\n", opts.kept_stacks);
        printf("(dry-run; pass --commit to delete)\n");
    }

    oci_store_close(store);
    free(default_root);
    return 0;
}

/* Argument parser state for oci rebuild-cache. Mirrors prune_args_t in
 * shape because both subcommands carry --store / --volume / --commit; the
 * two parsers stay disjoint so a future option addition to either does not
 * surprise the other.
 */
typedef struct {
    const char *store_root;
    const char *volume_root;
    bool commit;
} rebuild_cache_args_t;

static int parse_rebuild_cache_args(int argc,
                                    char **argv,
                                    rebuild_cache_args_t *out)
{
    int i = 1;
    while (i < argc) {
        const char *a = argv[i];
        if (a[0] != '-')
            break;
        if (!strcmp(a, "--")) {
            i++;
            break;
        }
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            return 1;
        } else if (!strcmp(a, "--commit")) {
            out->commit = true;
        } else if (!strcmp(a, "--store")) {
            if (++i >= argc) {
                fputs("error: --store needs an argument\n", stderr);
                return -1;
            }
            out->store_root = argv[i];
        } else if (!strcmp(a, "--volume")) {
            if (++i >= argc) {
                fputs("error: --volume needs an argument\n", stderr);
                return -1;
            }
            out->volume_root = argv[i];
        } else {
            fprintf(stderr, "error: unknown rebuild-cache option: %s\n", a);
            return -1;
        }
        i++;
    }
    if (i != argc) {
        fputs("error: rebuild-cache takes no positional arguments\n", stderr);
        return -1;
    }
    return 0;
}

static int cmd_rebuild_cache(int argc, char **argv)
{
    rebuild_cache_args_t args = {0};
    int prc = parse_rebuild_cache_args(argc, argv, &args);
    if (prc == 1)
        return print_usage(stdout);
    if (prc < 0)
        return 2;

    char *default_root = NULL;
    const char *store_root = args.store_root;
    if (!store_root) {
        default_root = oci_store_default_root();
        if (!default_root) {
            fprintf(stderr,
                    "error: could not determine default store root "
                    "(HOME not set?)\n");
            return 1;
        }
        store_root = default_root;
    }

    oci_store_t *store = oci_store_open(store_root);
    if (!store) {
        fprintf(stderr, "error: could not open store at %s: %s\n", store_root,
                strerror(errno));
        free(default_root);
        return 1;
    }

    oci_rebuild_cache_options_t opts = {
        .commit = args.commit,
    };
    const char *err = NULL;
    int rc = oci_rebuild_cache(store, args.volume_root, &opts, &err);
    if (rc < 0) {
        fprintf(stderr, "error: rebuild-cache failed: %s\n",
                err ? err : strerror(errno));
        oci_store_close(store);
        free(default_root);
        return 1;
    }

    size_t skipped_bad = opts.trees_skipped_no_origin +
                         opts.trees_skipped_bad_origin +
                         opts.trees_skipped_empty_diffids;

    if (args.commit) {
        printf("rebuild-cache:\n");
        printf("  scanned:        %zu unpacked trees\n", opts.trees_scanned);
        printf("  rebuilt:        %zu trees (%zu stack entries)\n",
               opts.trees_rebuilt, opts.stack_entries_added);
        printf("  already cached: %zu trees\n", opts.trees_skipped_cached);
        if (skipped_bad > 0)
            printf("  skipped (bad):  %zu trees\n", skipped_bad);
        if (opts.trees_failed > 0)
            printf("  failed:         %zu trees\n", opts.trees_failed);
    } else {
        printf("rebuild-cache (dry-run):\n");
        printf("  scanned:        %zu unpacked trees\n", opts.trees_scanned);
        printf("  would rebuild:  %zu trees (%zu stack entries)\n",
               opts.trees_rebuilt, opts.stack_entries_added);
        printf("  already cached: %zu trees\n", opts.trees_skipped_cached);
        if (skipped_bad > 0)
            printf("  skipped (bad):  %zu trees\n", skipped_bad);
        if (opts.trees_failed > 0)
            printf("  failed:         %zu trees\n", opts.trees_failed);
        printf("(dry-run; pass --commit to write)\n");
    }

    oci_store_close(store);
    free(default_root);
    return 0;
}

/* Argument parser state for `oci status`. The flag set is intentionally
 * small: store / volume mirrors prune / rebuild-cache, --json toggles the
 * structured output, --no-disk-usage is the operator escape hatch for very
 * large stores where the recursive size walk dominates wall time.
 */
typedef struct {
    const char *store_root;
    const char *volume_root;
    bool json;
    bool no_disk_usage;
} status_args_t;

static int parse_status_args(int argc, char **argv, status_args_t *out)
{
    int i = 1;
    while (i < argc) {
        const char *a = argv[i];
        if (a[0] != '-')
            break;
        if (!strcmp(a, "--")) {
            i++;
            break;
        }
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            return 1;
        } else if (!strcmp(a, "--json")) {
            out->json = true;
        } else if (!strcmp(a, "--no-disk-usage")) {
            out->no_disk_usage = true;
        } else if (!strcmp(a, "--store")) {
            if (++i >= argc) {
                fputs("error: --store needs an argument\n", stderr);
                return -1;
            }
            out->store_root = argv[i];
        } else if (!strcmp(a, "--volume")) {
            if (++i >= argc) {
                fputs("error: --volume needs an argument\n", stderr);
                return -1;
            }
            out->volume_root = argv[i];
        } else {
            fprintf(stderr, "error: unknown status option: %s\n", a);
            return -1;
        }
        i++;
    }
    if (i != argc) {
        fputs("error: status takes no positional arguments\n", stderr);
        return -1;
    }
    return 0;
}

/* Render a byte count compactly. Values >= 1 MiB use "~X.Y MiB", smaller
 * non-zero values render as raw bytes, zero stays "0 B". Mirrors the inspect
 * renderer's shared_bytes formatter so the two surfaces look consistent.
 */
static void format_bytes(uint64_t bytes, char *out, size_t cap)
{
    if (bytes == 0) {
        snprintf(out, cap, "0 B");
        return;
    }
    if (bytes >= (uint64_t) 1024 * 1024) {
        double mib = (double) bytes / (1024.0 * 1024.0);
        snprintf(out, cap, "~%.1f MiB", mib);
        return;
    }
    snprintf(out, cap, "%llu B", (unsigned long long) bytes);
}

/* Render epoch seconds as a fixed-width "YYYY-MM-DD HH:MM" string in local
 * time. Out buffer must hold at least 17 bytes. Negative or zero epochs
 * render as "(unknown)".
 */
static void format_mtime(int64_t epoch, char *out, size_t cap)
{
    if (epoch <= 0) {
        snprintf(out, cap, "(unknown)");
        return;
    }
    time_t t = (time_t) epoch;
    struct tm lt;
    if (!localtime_r(&t, &lt)) {
        snprintf(out, cap, "(unknown)");
        return;
    }
    strftime(out, cap, "%Y-%m-%d %H:%M", &lt);
}

/* Truncate a digest to "<algo>:<13-hex>..." so wide manifest digests still
 * align in the table. Mirrors the short_digest helper in inspect.c without
 * the dependency on that translation unit.
 */
static void short_digest(const char *full, char out[24])
{
    if (!full) {
        snprintf(out, 24, "(null)");
        return;
    }
    size_t len = strlen(full);
    if (len <= 22) {
        snprintf(out, 24, "%s", full);
        return;
    }
    snprintf(out, 24, "%.19s...", full);
}

static const char *pin_status_label(oci_status_pin_code_t c)
{
    switch (c) {
    case OCI_STATUS_PIN_OK:
        return "ok";
    case OCI_STATUS_PIN_MISSING_MANIFEST:
        return "missing manifest";
    case OCI_STATUS_PIN_CORRUPT_MANIFEST:
        return "corrupt manifest";
    case OCI_STATUS_PIN_CORRUPT_CONFIG:
        return "corrupt config";
    case OCI_STATUS_PIN_INDEX_NO_ARM64:
        return "no linux/arm64 entry";
    }
    return "unknown";
}

static const char *unpacked_status_label(oci_status_unpacked_code_t c)
{
    switch (c) {
    case OCI_STATUS_UNPACKED_OK:
        return "ok";
    case OCI_STATUS_UNPACKED_MISSING_ORIGIN:
        return "missing origin";
    case OCI_STATUS_UNPACKED_CORRUPT_ORIGIN:
        return "corrupt origin";
    }
    return "unknown";
}

/* Emit one JSON-quoted token with backslash and double-quote escaping.
 * Mirrors the print_quoted_token static in inspect.c without dragging the
 * dependency; control chars pass through (operator-facing strings, never
 * raw binary).
 */
static void emit_json_quoted(FILE *out, const char *s)
{
    fputc('"', out);
    if (s) {
        for (const char *p = s; *p; p++) {
            if (*p == '"' || *p == '\\')
                fputc('\\', out);
            fputc(*p, out);
        }
    }
    fputc('"', out);
}

static void render_status_human(FILE *out, const oci_status_t *st)
{
    /* Pins section. */
    if (st->pin_count == 0) {
        fprintf(out, "PINS (0): (none)\n\n");
    } else {
        fprintf(out, "PINS (%zu):\n", st->pin_count);
        for (size_t i = 0; i < st->pin_count; i++) {
            const oci_status_pin_entry_t *p = &st->pins[i];
            char short_d[24];
            short_digest(p->digest, short_d);
            if (p->status != OCI_STATUS_PIN_OK) {
                fprintf(out, "  %-40s  %-22s  (%s)\n",
                        p->name ? p->name : "(unknown)", short_d,
                        pin_status_label(p->status));
                continue;
            }
            char mtime_s[20];
            format_mtime(p->last_seen_mtime, mtime_s, sizeof(mtime_s));
            fprintf(out, "  %-40s  %-22s  %2zu layers   %s\n",
                    p->name ? p->name : "(unknown)", short_d, p->layer_count,
                    mtime_s);
        }
        fputc('\n', out);
    }

    /* Unpacked sysroots section. */
    if (st->unpacked_count == 0) {
        fprintf(out, "UNPACKED SYSROOTS (0): (none)\n\n");
    } else {
        fprintf(out, "UNPACKED SYSROOTS (%zu):\n", st->unpacked_count);
        for (size_t i = 0; i < st->unpacked_count; i++) {
            const oci_status_unpacked_entry_t *u = &st->unpacked[i];
            if (u->status != OCI_STATUS_UNPACKED_OK) {
                fprintf(out, "  %s  (%s)\n", u->path ? u->path : "(unknown)",
                        unpacked_status_label(u->status));
                continue;
            }
            char short_d[24];
            short_digest(u->manifest_digest, short_d);
            char bytes_s[24];
            if (st->disk_usage_skipped)
                snprintf(bytes_s, sizeof(bytes_s), "(skipped)");
            else
                format_bytes(u->tree_bytes, bytes_s, sizeof(bytes_s));
            fprintf(out, "  %s  %-22s  %s\n", u->path ? u->path : "(unknown)",
                    short_d, bytes_s);
        }
        fputc('\n', out);
    }

    /* Store totals section. */
    char blob_b[24], layer_b[24], stack_b[24], total_b[24];
    if (st->disk_usage_skipped) {
        snprintf(blob_b, sizeof(blob_b), "(skipped)");
        snprintf(layer_b, sizeof(layer_b), "(skipped)");
        snprintf(stack_b, sizeof(stack_b), "(skipped)");
        snprintf(total_b, sizeof(total_b), "(skipped)");
    } else {
        format_bytes(st->blob_bytes_total, blob_b, sizeof(blob_b));
        format_bytes(st->layer_cache_bytes_total, layer_b, sizeof(layer_b));
        format_bytes(st->stack_cache_bytes_total, stack_b, sizeof(stack_b));
        uint64_t total = st->blob_bytes_total + st->layer_cache_bytes_total +
                         st->stack_cache_bytes_total;
        format_bytes(total, total_b, sizeof(total_b));
    }
    fprintf(out, "STORE TOTALS:\n");
    fprintf(out, "  blobs:        %zu   (%s)\n", st->blob_count, blob_b);
    fprintf(out, "  layers raw:   %zu of %zu reachable cached   (%s)\n",
            st->diff_ids_populated, st->diff_ids_reachable, layer_b);
    fprintf(out, "  layers stack: %zu of %zu reachable cached   (%s)\n",
            st->chain_ids_populated, st->chain_ids_reachable, stack_b);
    fprintf(out, "  total:        %s\n", total_b);
    if (st->disk_usage_skipped)
        fprintf(out, "  (disk usage skipped)\n");
}

static void render_status_json(FILE *out, const oci_status_t *st)
{
    fprintf(out, "{\"schemaVersion\":1,\"pins\":[");
    for (size_t i = 0; i < st->pin_count; i++) {
        const oci_status_pin_entry_t *p = &st->pins[i];
        if (i > 0)
            fputc(',', out);
        fprintf(out, "{\"name\":");
        emit_json_quoted(out, p->name);
        fprintf(out, ",\"digest\":");
        emit_json_quoted(out, p->digest);
        fprintf(out,
                ",\"manifest_size\":%llu,\"config_size\":%llu,\"layer_count\":"
                "%zu,\"last_seen_mtime\":%lld,\"status\":\"%s\"}",
                (unsigned long long) p->manifest_size,
                (unsigned long long) p->config_size, p->layer_count,
                (long long) p->last_seen_mtime, pin_status_label(p->status));
    }
    fprintf(out, "],\"unpacked\":[");
    for (size_t i = 0; i < st->unpacked_count; i++) {
        const oci_status_unpacked_entry_t *u = &st->unpacked[i];
        if (i > 0)
            fputc(',', out);
        fprintf(out, "{\"path\":");
        emit_json_quoted(out, u->path);
        fprintf(out, ",\"manifest_digest\":");
        emit_json_quoted(out, u->manifest_digest);
        fprintf(out,
                ",\"layer_count\":%zu,\"tree_bytes\":%llu,\"status\":\"%s\"}",
                u->layer_count, (unsigned long long) u->tree_bytes,
                unpacked_status_label(u->status));
    }
    fprintf(out, "],\"totals\":{");
    fprintf(out, "\"blob_count\":%zu,\"blob_bytes\":%llu,", st->blob_count,
            (unsigned long long) st->blob_bytes_total);
    fprintf(out, "\"layer_cache_count\":%zu,\"layer_cache_bytes\":%llu,",
            st->layer_cache_count,
            (unsigned long long) st->layer_cache_bytes_total);
    fprintf(out, "\"stack_cache_count\":%zu,\"stack_cache_bytes\":%llu,",
            st->stack_cache_count,
            (unsigned long long) st->stack_cache_bytes_total);
    fprintf(out, "\"diff_ids_reachable\":%zu,\"diff_ids_populated\":%zu,",
            st->diff_ids_reachable, st->diff_ids_populated);
    fprintf(out, "\"chain_ids_reachable\":%zu,\"chain_ids_populated\":%zu,",
            st->chain_ids_reachable, st->chain_ids_populated);
    fprintf(out, "\"disk_usage_skipped\":%s",
            st->disk_usage_skipped ? "true" : "false");
    fprintf(out, "}}\n");
}

static int cmd_status(int argc, char **argv)
{
    status_args_t args = {0};
    int prc = parse_status_args(argc, argv, &args);
    if (prc == 1)
        return print_usage(stdout);
    if (prc < 0)
        return 2;

    char *default_root = NULL;
    const char *store_root = args.store_root;
    if (!store_root) {
        default_root = oci_store_default_root();
        if (!default_root) {
            fprintf(stderr,
                    "error: could not determine default store root "
                    "(HOME not set?)\n");
            return 1;
        }
        store_root = default_root;
    }

    oci_store_t *store = oci_store_open(store_root);
    if (!store) {
        fprintf(stderr, "error: could not open store at %s: %s\n", store_root,
                strerror(errno));
        free(default_root);
        return 1;
    }

    oci_status_options_t sopts = {
        .volume_root = args.volume_root,
        .skip_disk_usage = args.no_disk_usage,
    };
    oci_status_t st = {0};
    const char *err = NULL;
    if (oci_status_compute(store, &sopts, &st, &err) < 0) {
        fprintf(stderr, "error: status failed: %s\n",
                err ? err : strerror(errno));
        oci_status_free(&st);
        oci_store_close(store);
        free(default_root);
        return 1;
    }

    if (args.json)
        render_status_json(stdout, &st);
    else
        render_status_human(stdout, &st);

    oci_status_free(&st);
    oci_store_close(store);
    free(default_root);
    return 0;
}

int oci_cli_main(int argc, char **argv)
{
    /* Multicall entry: main() forwards the full command line when argv[0] is
     * an alias symlink (BusyBox-style), so brand all usage text with the
     * basename the user invoked instead of the "elfuse oci" spelling.
     */
    if (argc >= 1 && argv[0]) {
        const char *slash = strrchr(argv[0], '/');
        const char *invoked = slash ? slash + 1 : argv[0];
        if (strcmp(invoked, "oci") != 0)
            cli_name = invoked;
    }

    if (argc < 2)
        return print_usage(stderr);

    const char *sub = argv[1];
    if (!strcmp(sub, "-h") || !strcmp(sub, "--help") || !strcmp(sub, "help"))
        return print_usage(stdout);
    if (!strcmp(sub, "inspect"))
        return cmd_inspect(argc - 1, argv + 1);
    if (!strcmp(sub, "pull"))
        return cmd_pull(argc - 1, argv + 1);
    if (!strcmp(sub, "unpack"))
        return cmd_unpack(argc - 1, argv + 1);
    if (!strcmp(sub, "clone"))
        return cmd_clone(argc - 1, argv + 1);
    if (!strcmp(sub, "run"))
        return oci_cli_run(argc - 1, argv + 1);
    if (!strcmp(sub, "prune"))
        return cmd_prune(argc - 1, argv + 1);
    if (!strcmp(sub, "rebuild-cache"))
        return cmd_rebuild_cache(argc - 1, argv + 1);
    if (!strcmp(sub, "status"))
        return cmd_status(argc - 1, argv + 1);
    if (!strcmp(sub, "list") || !strcmp(sub, "ls"))
        return cmd_not_implemented("list");

    fprintf(stderr, "error: unknown oci subcommand: %s\n", sub);
    return print_usage(stderr);
}
