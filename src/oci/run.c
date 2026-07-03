/* elfuse oci run -- unpack + clone + runspec + path resolve + launch
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implementation walks the orchestration steps in this order:
 *
 *   1. resolve ref against the local store (must already be pulled)
 *   2. oci_unpack into the APFS sysroot volume (idempotent; no-op if
 *      layers already extracted)
 *   3. oci_clone_rootfs into <volume>/runs/<id>/
 *   4. read + parse the manifest, then the image config, off the blob
 *      store via oci_blob_store_path + a small read-into-heap helper
 *      (parallel to src/oci/inspect.c's read_blob_file; intentionally
 *      duplicated rather than re-exported because the inspect copy
 *      lives behind a static and a cross-module hoist would expand the
 *      public surface for a 50-line helper)
 *   5. oci_runspec_build folds the image runtime + CLI flags into
 *      argv/envp/cwd/uid
 *   6. materialize spec.cwd under run_dir (mkdir -p, mode 0755)
 *   7. oci_path_resolve resolves spec.argv[0] against the merged PATH
 *      inside run_dir (sysroot containment included)
 *   8. replace spec.argv[0] with the guest-absolute path the resolver
 *      handed back, so the guest sees its own canonical name
 *   9. save host cwd, chdir to <run_dir><spec.cwd> so the guest's
 *      inherited cwd matches the OCI WorkingDir
 *  10. assemble launch_args_t and dispatch to elfuse_launch (or to the
 *      test override when oci_run_set_launch_for_testing is in effect)
 *  11. restore host cwd, free intermediate state, remove the clone dir
 *      unless keep_rootfs is set
 *
 * Errors at any stage funnel through the same cleanup epilogue. The
 * clone directory is removed on launch failure too, matching the
 * "ephemeral by default" design decision; --keep is the only way to
 * opt out.
 */

#include "run.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "blob-store.h"
#include "cli.h"
#include "clone-rootfs.h"
#include "digest.h"
#include "manifest.h"
#include "path-resolve.h"
#include "runtime-files.h"
#include "unpack.h"
#include "volume.h"

#include "core/launch.h"

#include "debug/log.h"
#include "util.h"

/* Process-global launch backend pointer. NULL means "use the default
 * (elfuse_launch)". Toggled by oci_run_set_launch_for_testing; nobody
 * else writes it. The indirection lets tests assert on the
 * launch_args_t shape without spinning up an HVF VM.
 */
static oci_run_launch_fn_t g_launch_override = NULL;

void oci_run_set_launch_for_testing(oci_run_launch_fn_t fn)
{
    g_launch_override = fn;
}

/* Read a blob from the store into a heap buffer. Parallel to the
 * read_blob_file helper that lives behind a static in src/oci/inspect.c;
 * the 50 lines here intentionally duplicate that helper rather than
 * hoisting it into a public utility, because the inspect path needs
 * subtly different error reporting (a "blob missing" warning that goes
 * to stderr) and a hoist would have to keep both shapes alive.
 */
static int load_blob(oci_blob_store_t *blobs,
                     oci_digest_algo_t algo,
                     const char *hex,
                     char **out_body,
                     size_t *out_len,
                     const char **err)
{
    char path[4096];
    int n = oci_blob_store_path(blobs, algo, hex, path, sizeof(path));
    if (n < 0 || (size_t) n >= sizeof(path)) {
        oci_err_static(err, "blob path too long");
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        oci_err_fmt(err, "cannot open blob %s: %s", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved = errno;
        close(fd);
        oci_err_static(err, "fstat on blob failed");
        errno = saved;
        return -1;
    }
    if (st.st_size < 0 || st.st_size > 64 * 1024 * 1024) {
        close(fd);
        oci_err_static(err, "blob too large");
        errno = EFBIG;
        return -1;
    }
    size_t want = (size_t) st.st_size;
    char *buf = malloc(want + 1);
    if (!buf) {
        close(fd);
        oci_err_static(err, "out of memory loading blob");
        errno = ENOMEM;
        return -1;
    }
    size_t off = 0;
    while (off < want) {
        ssize_t r = read(fd, buf + off, want - off);
        if (r < 0) {
            int saved = errno;
            free(buf);
            close(fd);
            oci_err_static(err, "read on blob failed");
            errno = saved;
            return -1;
        }
        if (r == 0)
            break;
        off += (size_t) r;
    }
    close(fd);
    if (off != want) {
        free(buf);
        oci_err_static(err, "short read on blob");
        errno = EIO;
        return -1;
    }
    buf[want] = '\0';
    *out_body = buf;
    *out_len = want;
    return 0;
}

/* Resolve the manifest blob pinned at digest_str. If the blob is an
 * image index (the shape docker.io multi-arch tags such as alpine:3
 * pin to by default), drill into the linux/arm64 leaf descriptor and
 * re-load that blob; the leaf body is what oci_manifest_parse expects.
 * The mirror of this classify-then-walk path lives in src/oci/inspect.c;
 * keep the two in sync. On success returns 0 with *out_body holding the
 * leaf-manifest bytes, *out_len its length, and *out_mf the parsed
 * shape. The caller frees *out_body via free() and *out_mf via
 * oci_manifest_free(); on failure both stay untouched and the helper
 * cleans up its own intermediate state.
 */
static int resolve_image_manifest(oci_store_t *store,
                                  const char *digest_str,
                                  char **out_body,
                                  size_t *out_len,
                                  oci_manifest_t *out_mf,
                                  const char **err)
{
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(digest_str, &algo, hex)) {
        oci_err_static(err, "pinned manifest digest is malformed");
        errno = EINVAL;
        return -1;
    }

    char *body = NULL;
    size_t len = 0;
    if (load_blob(oci_store_blobs(store), algo, hex, &body, &len, err) < 0)
        return -1;

    /* Classify. Index and manifest are disjoint JSON shapes (one
     * requires "manifests", the other requires "config" + "layers"),
     * so a successful parse is unambiguous. Drilling happens only when
     * the index parse wins; the leaf-pinned shape (the fixture-builder
     * and tests/test-oci-compat.sh path) falls through directly to the
     * manifest parser below.
     */
    oci_index_t idx = {0};
    if (oci_index_parse(body, len, &idx, NULL) == 0) {
        const oci_index_entry_t *picked = oci_index_pick_linux_arm64(&idx);
        if (!picked) {
            oci_index_free(&idx);
            free(body);
            oci_err_static(err, "image index has no linux/arm64 entry");
            errno = ENOENT;
            return -1;
        }
        char *sub_body = NULL;
        size_t sub_len = 0;
        if (load_blob(oci_store_blobs(store), picked->desc.algo,
                      picked->desc.hex, &sub_body, &sub_len, err) < 0) {
            oci_index_free(&idx);
            free(body);
            return -1;
        }
        oci_index_free(&idx);
        free(body);
        body = sub_body;
        len = sub_len;
    }

    oci_manifest_t mf = {0};
    const char *mparse_err = NULL;
    if (oci_manifest_parse(body, len, &mf, &mparse_err) < 0) {
        oci_err_fmt(err, "manifest parse failed: %s",
                    mparse_err ? mparse_err : "(no message)");
        free(body);
        errno = EPROTO;
        return -1;
    }

    *out_body = body;
    *out_len = len;
    *out_mf = mf;
    return 0;
}

int oci_run_resolve_image_manifest_for_testing(oci_store_t *store,
                                               const char *digest_str,
                                               char **out_body,
                                               size_t *out_len,
                                               oci_manifest_t *out_mf,
                                               const char **err)
{
    if (err)
        *err = NULL;
    if (!store || !digest_str || !out_body || !out_len || !out_mf) {
        oci_err_static(err, "resolve_image_manifest: NULL argument");
        errno = EINVAL;
        return -1;
    }
    return resolve_image_manifest(store, digest_str, out_body, out_len, out_mf,
                                  err);
}

/* Concatenate two path components with one slash boundary. Caller frees
 * the result.
 */
static char *path_join_heap(const char *a, const char *b)
{
    if (!a)
        return b ? strdup(b) : NULL;
    if (!b)
        return strdup(a);
    size_t alen = strlen(a);
    size_t blen = strlen(b);
    bool a_trail = alen > 0 && a[alen - 1] == '/';
    bool b_lead = blen > 0 && b[0] == '/';
    char *r = malloc(alen + blen + 2);
    if (!r)
        return NULL;
    if (a_trail && b_lead) {
        memcpy(r, a, alen);
        memcpy(r + alen, b + 1, blen - 1);
        r[alen + blen - 1] = '\0';
    } else if (!a_trail && !b_lead && alen > 0 && blen > 0) {
        memcpy(r, a, alen);
        r[alen] = '/';
        memcpy(r + alen + 1, b, blen);
        r[alen + 1 + blen] = '\0';
    } else {
        memcpy(r, a, alen);
        memcpy(r + alen, b, blen);
        r[alen + blen] = '\0';
    }
    return r;
}

/* Recursive mkdir; tolerates existing intermediate directories. Each
 * newly created segment is chowned to (spec.uid, spec.gid) when
 * has_creds is set; macOS rejects fchownat for non-root callers
 * spoofing arbitrary uids, so the chown is best effort and silently
 * ignored when it fails. The intended ownership is also recorded by
 * the sidecar metadata that a future syscall-layer change will read;
 * for now the host inode owner stays the invoking user.
 */
static int mkdir_p_owned(const char *path,
                         mode_t mode,
                         uint32_t uid,
                         uint32_t gid,
                         bool has_creds,
                         const char **err)
{
    if (!path || !*path) {
        oci_err_static(err, "empty path in mkdir_p");
        errno = EINVAL;
        return -1;
    }
    /* Walk segments; create each prefix. */
    char *dup = strdup(path);
    if (!dup) {
        oci_err_static(err, "out of memory in mkdir_p");
        errno = ENOMEM;
        return -1;
    }
    for (char *p = dup + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(dup, mode) < 0 && errno != EEXIST) {
            int saved = errno;
            oci_err_fmt(err, "mkdir %s failed: %s", dup, strerror(saved));
            free(dup);
            errno = saved;
            return -1;
        }
        if (has_creds)
            (void) chown(dup, uid, gid);
        *p = '/';
    }
    if (mkdir(dup, mode) < 0 && errno != EEXIST) {
        int saved = errno;
        oci_err_fmt(err, "mkdir %s failed: %s", dup, strerror(saved));
        free(dup);
        errno = saved;
        return -1;
    }
    if (has_creds)
        (void) chown(dup, uid, gid);
    free(dup);
    return 0;
}

/* Pull PATH=... out of a NULL-terminated envp. Returns the value
 * pointer (not strdup'd) or NULL if no PATH key is present.
 */
static const char *envp_get_path(const char *const *envp)
{
    if (!envp)
        return NULL;
    for (size_t i = 0; envp[i]; i++) {
        if (strncmp(envp[i], "PATH=", 5) == 0)
            return envp[i] + 5;
    }
    return NULL;
}

/* Count entries in a NULL-terminated string vector. */
static int strvec_count(char *const *v)
{
    int n = 0;
    if (!v)
        return 0;
    while (v[n])
        n++;
    return n;
}

int oci_run(oci_store_t *store,
            const oci_ref_t *ref,
            const oci_run_options_t *opts,
            const char *const *host_environ,
            const char **err)
{
    if (err)
        *err = NULL;
    if (!store || !ref || !opts) {
        oci_err_static(err, "oci_run: NULL store/ref/opts");
        errno = EINVAL;
        return -1;
    }
    /* Suppress unused warnings for fields kept on the options struct
     * for forward compatibility with features not yet wired
     * (clone_name -> deterministic run-dir, store_dir -> consumed by
     * the caller before this function sees the store).
     */
    (void) opts->store_dir;
    (void) opts->clone_name;

    char *image_dir = NULL;
    char *volume_root = NULL;
    char *run_dir = NULL;
    char *manifest_body = NULL;
    char *config_body = NULL;
    char *host_argv0 = NULL;
    char *guest_argv0 = NULL;
    char *cwd_host = NULL;
    oci_manifest_t mf = {0};
    oci_image_config_t cfg = {0};
    oci_runspec_t spec = {0};
    int rc = -1;
    char host_cwd[PATH_MAX];
    bool have_host_cwd = (getcwd(host_cwd, sizeof(host_cwd)) != NULL);

    /* 1. unpack (idempotent). */
    oci_unpack_options_t uopts = {
        .volume_root = opts->volume_dir, .quiet = true, .force_relayer = false};
    const char *unpack_err = NULL;
    if (oci_unpack(store, ref, &uopts, &image_dir, &unpack_err) < 0) {
        oci_err_fmt(err, "unpack failed: %s",
                    unpack_err ? unpack_err : strerror(errno));
        goto out;
    }

    /* 2. resolve volume root (clone-rootfs lands under <volume>/runs/). */
    const char *vol_err = NULL;
    if (oci_volume_ensure(opts->volume_dir, &volume_root, &vol_err) < 0) {
        oci_err_fmt(err, "volume_ensure failed: %s",
                    vol_err ? vol_err : strerror(errno));
        goto out;
    }

    /* 3. clone-rootfs. image_dir has a trailing slash; strip for the
     * source argument so the inner code joins correctly.
     */
    size_t il = strlen(image_dir);
    if (il > 1 && image_dir[il - 1] == '/')
        image_dir[il - 1] = '\0';
    const char *clone_err = NULL;
    if (oci_clone_rootfs(image_dir, volume_root, &run_dir, &clone_err) < 0) {
        oci_err_fmt(err, "clone-rootfs failed: %s",
                    clone_err ? clone_err : strerror(errno));
        goto out;
    }

    /* 3.5. inject host-truth /etc/{resolv.conf,hosts,hostname} so
     * guest libc lookups (getaddrinfo, gethostname, /etc/hosts walks)
     * match the macOS host instead of the image's containerd
     * defaults. Failure tears the clone-rootfs back down through the
     * existing cleanup epilogue.
     */
    const char *rfi_err = NULL;
    if (oci_runtime_files_inject(run_dir, &rfi_err) < 0) {
        oci_err_fmt(err, "runtime-files inject failed: %s",
                    rfi_err ? rfi_err : strerror(errno));
        goto out;
    }

    /* 4. read manifest blob, then config blob, then parse both. The
     * manifest read goes through resolve_image_manifest, which
     * transparently walks one image-index indirection when the pin
     * lands on a multi-arch index (the docker.io default for tags like
     * alpine:3).
     */
    char *manifest_digest_str = NULL;
    const char *getref_err = NULL;
    if (oci_store_get_ref(store, ref, &manifest_digest_str, &getref_err) < 0) {
        oci_err_fmt(err, "no pin for ref: %s",
                    getref_err ? getref_err : strerror(errno));
        goto out;
    }
    size_t manifest_len = 0;
    int rcm = resolve_image_manifest(store, manifest_digest_str, &manifest_body,
                                     &manifest_len, &mf, err);
    free(manifest_digest_str);
    if (rcm < 0)
        goto out;
    size_t config_len = 0;
    if (load_blob(oci_store_blobs(store), mf.config.algo, mf.config.hex,
                  &config_body, &config_len, err) < 0)
        goto out;
    const char *cparse_err = NULL;
    if (oci_image_config_parse(config_body, config_len, &cfg, &cparse_err) <
        0) {
        oci_err_fmt(err, "image config parse failed: %s",
                    cparse_err ? cparse_err : "(no message)");
        goto out;
    }

    /* 5. fold runtime + CLI overrides into argv/envp/cwd/uid. Layer
     * the unpacked clone-rootfs over the caller's flags so the runspec
     * resolver can read /etc/passwd and /etc/group for symbolic User
     * resolution. The caller-side flags stay const; only the local
     * copy points the resolver at the rootfs.
     */
    oci_runspec_flags_t spec_flags = opts->spec;
    spec_flags.rootfs_for_nss = run_dir;
    const char *rs_err = NULL;
    if (oci_runspec_build(&cfg.config, &spec_flags, host_environ, &spec,
                          &rs_err) < 0) {
        oci_err_fmt(err, "runspec build failed: %s",
                    rs_err ? rs_err : strerror(errno));
        goto out;
    }

    /* 6. materialize spec.cwd under run_dir. */
    cwd_host = path_join_heap(run_dir, spec.cwd);
    if (!cwd_host) {
        oci_err_static(err, "out of memory building cwd host path");
        errno = ENOMEM;
        goto out;
    }
    if (mkdir_p_owned(cwd_host, 0755, spec.uid, spec.gid, spec.has_creds, err) <
        0)
        goto out;

    /* 7. PATH-resolve argv[0]. */
    if (!spec.argv || !spec.argv[0]) {
        oci_err_static(err, "runspec produced empty argv");
        errno = EINVAL;
        goto out;
    }
    const char *path_env = envp_get_path((const char *const *) spec.envp);
    const char *pr_err = NULL;
    if (oci_path_resolve(run_dir, spec.argv[0], path_env, spec.cwd, &host_argv0,
                         &guest_argv0, &pr_err) < 0) {
        oci_err_fmt(err, "%s", pr_err ? pr_err : "argv[0] resolution failed");
        goto out;
    }

    /* 8. swap spec.argv[0] for the guest-absolute path the resolver
     * handed back. The guest reads /proc/self/exe + argv[0] and expects
     * the canonical name it would have seen via execvp.
     */
    free(spec.argv[0]);
    spec.argv[0] = guest_argv0;
    guest_argv0 = NULL; /* ownership transferred to spec */

    /* 8b. expand any shebang chain on the resolved entrypoint. In-guest
     * execve(2) of scripts is handled by the syscall layer, but the
     * initial launch loads *host_argv0 directly, and images routinely
     * front their Entrypoint with a /bin/sh wrapper script.
     */
    if (oci_shebang_expand(run_dir, spec.cwd, &host_argv0, &spec.argv,
                           &pr_err) < 0) {
        oci_err_fmt(err, "%s", pr_err ? pr_err : "shebang expansion failed");
        goto out;
    }

    /* 9. chdir into the materialized WorkingDir so the guest inherits
     * its OCI cwd.
     */
    if (chdir(cwd_host) < 0) {
        oci_err_fmt(err, "chdir into '%s' failed: %s", cwd_host,
                    strerror(errno));
        goto out;
    }

    /* 10. assemble launch_args and dispatch. */
    launch_args_t la = {
        .elf_path = host_argv0,
        .sysroot = run_dir,
        .guest_argc = strvec_count(spec.argv),
        .guest_argv = (const char **) spec.argv,
        .envp = (const char **) spec.envp,
        .has_creds = spec.has_creds,
        .uid = spec.uid,
        .gid = spec.gid,
        .cwd_guest = spec.cwd,
        .gdb_port = 0,
        .gdb_stop_on_entry = false,
        .timeout_sec = 10,
        .fork_child_fd = -1,
        .vfork_notify_fd = -1,
        .verbose = false,
    };
    oci_run_launch_fn_t launch =
        g_launch_override ? g_launch_override : elfuse_launch;
    rc = launch(&la);

    /* 11. restore host cwd before cleanup so subsequent paths
     * (clone-rootfs-remove, sysroot detach) operate from a sane place.
     */
    if (have_host_cwd && chdir(host_cwd) < 0) {
        log_warn("could not restore host cwd to %s: %s", host_cwd,
                 strerror(errno));
        (void) chdir("/");
    }

out:
    if (run_dir && !opts->keep_rootfs) {
        const char *rm_err = NULL;
        if (oci_clone_rootfs_remove(run_dir, &rm_err) < 0)
            log_warn("clone-rootfs cleanup partial: %s",
                     rm_err ? rm_err : strerror(errno));
    }
    free(host_argv0);
    free(guest_argv0);
    free(cwd_host);
    oci_runspec_free(&spec);
    oci_image_config_free(&cfg);
    oci_manifest_free(&mf);
    free(config_body);
    free(manifest_body);
    free(run_dir);
    free(volume_root);
    free(image_dir);
    return rc;
}

/* ── CLI entry ─────────────────────────────────────────────────── */

static int print_run_usage(FILE *out)
{
    fprintf(out, "usage: %s run [OPTIONS] IMAGE [ARG...]\n", oci_cli_name());
    fputs(
        "\n"
        "Run a binary from an already-pulled OCI image. The image's\n"
        "Entrypoint/Cmd/Env/WorkingDir/User are honored; CLI flags\n"
        "override individual fields.\n"
        "\n"
        "Options:\n"
        "  --store DIR           Override the local store root\n"
        "  --volume DIR          Override the sysroot APFS volume\n"
        "  --entrypoint PROG     Replace the image Entrypoint\n"
        "  -e, --env KEY=VAL     Set or replace env var\n"
        "  -e, --env KEY         Import KEY from host environ\n"
        "  -w, --workdir DIR     Override image WorkingDir\n"
        "  -u, --user UID[:GID]  Override image User (numeric or "
        "name[:group])\n"
        "  --keep                Keep the per-run rootfs after exit\n"
        "  --name NAME           Reserved: deterministic clone dir\n"
        "                        (currently ignored)\n"
        "\n"
        "IMAGE follows the docker/containerd grammar (alpine,\n"
        "alpine:3.20, ghcr.io/owner/img:tag, etc.). The image must\n"
        "already be pulled; this subcommand does not auto-pull.\n",
        out);
    return out == stderr ? 2 : 0;
}

extern char **environ;

int oci_cli_run(int argc, char **argv)
{
    oci_run_options_t opts = {0};
    const char **env_overrides = NULL;
    size_t n_overrides = 0;
    size_t cap_overrides = 0;

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
            free(env_overrides);
            return print_run_usage(stdout);
        }
        if (!strcmp(a, "--store")) {
            if (++i >= argc) {
                fputs("error: --store needs an argument\n", stderr);
                free(env_overrides);
                return 2;
            }
            opts.store_dir = argv[i];
        } else if (!strcmp(a, "--volume")) {
            if (++i >= argc) {
                fputs("error: --volume needs an argument\n", stderr);
                free(env_overrides);
                return 2;
            }
            opts.volume_dir = argv[i];
        } else if (!strcmp(a, "--entrypoint")) {
            if (++i >= argc) {
                fputs("error: --entrypoint needs an argument\n", stderr);
                free(env_overrides);
                return 2;
            }
            opts.spec.entrypoint_override = argv[i];
        } else if (!strcmp(a, "-e") || !strcmp(a, "--env")) {
            if (++i >= argc) {
                fputs("error: -e/--env needs an argument\n", stderr);
                free(env_overrides);
                return 2;
            }
            if (n_overrides + 1 > cap_overrides) {
                size_t newcap = cap_overrides ? cap_overrides * 2 : 8;
                const char **np = realloc(env_overrides, newcap * sizeof(*np));
                if (!np) {
                    fputs("error: out of memory\n", stderr);
                    free(env_overrides);
                    return 1;
                }
                env_overrides = np;
                cap_overrides = newcap;
            }
            env_overrides[n_overrides++] = argv[i];
        } else if (!strcmp(a, "-w") || !strcmp(a, "--workdir")) {
            if (++i >= argc) {
                fputs("error: -w/--workdir needs an argument\n", stderr);
                free(env_overrides);
                return 2;
            }
            opts.spec.workdir_override = argv[i];
        } else if (!strcmp(a, "-u") || !strcmp(a, "--user")) {
            if (++i >= argc) {
                fputs("error: -u/--user needs an argument\n", stderr);
                free(env_overrides);
                return 2;
            }
            opts.spec.user_override = argv[i];
        } else if (!strcmp(a, "--keep")) {
            opts.keep_rootfs = true;
        } else if (!strcmp(a, "--name")) {
            if (++i >= argc) {
                fputs("error: --name needs an argument\n", stderr);
                free(env_overrides);
                return 2;
            }
            opts.clone_name = argv[i];
        } else {
            fprintf(stderr, "error: unknown option: %s\n", a);
            free(env_overrides);
            return 2;
        }
        i++;
    }
    if (i >= argc) {
        fputs("error: oci run needs IMAGE\n", stderr);
        free(env_overrides);
        return 2;
    }
    const char *ref_str = argv[i];
    i++;
    opts.spec.env_overrides = env_overrides;
    opts.spec.nenv_overrides = n_overrides;
    opts.spec.positional_argc = argc - i;
    opts.spec.positional_argv = (const char *const *) (argv + i);

    oci_ref_t ref = {0};
    const char *parse_err = NULL;
    if (oci_ref_parse(ref_str, &ref, &parse_err) < 0) {
        fprintf(stderr, "error: invalid reference: %s\n",
                parse_err ? parse_err : "(unknown)");
        free(env_overrides);
        return 1;
    }

    char *default_root = NULL;
    const char *store_root = opts.store_dir;
    if (!store_root) {
        default_root = oci_store_default_root();
        if (!default_root) {
            fputs("error: cannot determine default store root (HOME?)\n",
                  stderr);
            oci_ref_free(&ref);
            free(env_overrides);
            return 1;
        }
        store_root = default_root;
    }
    oci_store_t *store = oci_store_open(store_root);
    if (!store) {
        fprintf(stderr, "error: cannot open store at %s: %s\n", store_root,
                strerror(errno));
        oci_ref_free(&ref);
        free(default_root);
        free(env_overrides);
        return 1;
    }

    const char *run_err = NULL;
    int rc =
        oci_run(store, &ref, &opts, (const char *const *) environ, &run_err);
    if (rc < 0) {
        fprintf(stderr, "error: oci run failed: %s\n",
                run_err ? run_err : strerror(errno));
        rc = 1;
    }

    oci_store_close(store);
    oci_ref_free(&ref);
    free(default_root);
    free(env_overrides);
    return rc;
}
