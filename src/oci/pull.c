/* `elfuse oci pull` implementation: skopeo transfer + local pin
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * See pull.h for the design rationale. The wrapper's failure surface is
 * deliberately small: build argv, run skopeo, read back the digest it
 * attests via --digestfile, pin it. Everything protocol-shaped (auth,
 * TLS, retries, resume, mirrors) is skopeo configuration, not elfuse
 * code.
 */

#include "pull.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static _Thread_local char pull_err_buf[512];

static int set_err_fmt(const char **err_msg, int err_no, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static int set_err_fmt(const char **err_msg, int err_no, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(pull_err_buf, sizeof(pull_err_buf), fmt, ap);
    va_end(ap);
    if (err_msg)
        *err_msg = pull_err_buf;
    errno = err_no;
    return -1;
}

int oci_pull(oci_store_t *store,
             const char *store_root,
             const oci_ref_t *ref,
             const oci_pull_options_t *opts,
             const char **err_msg)
{
    if (!store || !store_root || !ref)
        return set_err(err_msg, "pull: NULL argument", EINVAL);

    const char *arch = (opts && opts->arch) ? opts->arch : "arm64";
    bool quiet = opts && opts->quiet;

    char *canonical = oci_ref_canonical(ref);
    if (!canonical)
        return set_err(err_msg, "pull: canonical render failed", ENOMEM);

    char src[1024];
    char dst[1024];
    char digestfile[1024];
    int n1 = snprintf(src, sizeof(src), "docker://%s", canonical);
    int n2 = snprintf(dst, sizeof(dst), "oci:%s", store_root);
    int n3 = snprintf(digestfile, sizeof(digestfile),
                      "%s/tmp/pull-digest-%d-XXXXXX", store_root, getpid());
    free(canonical);
    if (n1 < 0 || (size_t) n1 >= sizeof(src) || n2 < 0 ||
        (size_t) n2 >= sizeof(dst) || n3 < 0 ||
        (size_t) n3 >= sizeof(digestfile))
        return set_err(err_msg, "pull: reference too long", ENAMETOOLONG);

    int dfd = mkstemp(digestfile);
    if (dfd < 0)
        return set_err(err_msg, "pull: digestfile create failed", errno);
    close(dfd);

    /* --override-os/arch resolve multi-arch tags to the guest platform
     * elfuse will actually execute; the pin then names the platform
     * leaf, which oci run consumes directly.
     */
    const char *argv[16];
    int argc = 0;
    argv[argc++] = "skopeo";
    argv[argc++] = "copy";
    argv[argc++] = "--override-os";
    argv[argc++] = "linux";
    argv[argc++] = "--override-arch";
    argv[argc++] = arch;
    argv[argc++] = "--digestfile";
    argv[argc++] = digestfile;
    if (quiet)
        argv[argc++] = "-q";
    argv[argc++] = src;
    argv[argc++] = dst;
    argv[argc] = NULL;

    pid_t pid = -1;
    int rc =
        posix_spawnp(&pid, "skopeo", NULL, NULL, (char *const *) argv, environ);
    if (rc != 0) {
        unlink(digestfile);
        if (rc == ENOENT)
            return set_err(err_msg,
                           "pull: skopeo not found; install it with "
                           "`brew install skopeo` (macOS) or your package "
                           "manager",
                           ENOENT);
        return set_err_fmt(err_msg, rc, "pull: skopeo spawn failed: %s",
                           strerror(rc));
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            unlink(digestfile);
            return set_err(err_msg, "pull: waitpid failed", errno);
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        unlink(digestfile);
        if (WIFSIGNALED(status))
            return set_err_fmt(err_msg, EINTR,
                               "pull: skopeo terminated by signal %d",
                               WTERMSIG(status));
        return set_err_fmt(err_msg, EIO, "pull: skopeo copy failed (exit %d)",
                           WEXITSTATUS(status));
    }

    /* skopeo attests the copied manifest digest via --digestfile. */
    char digest[256] = {0};
    FILE *f = fopen(digestfile, "r");
    if (!f || !fgets(digest, sizeof(digest), f)) {
        if (f)
            fclose(f);
        unlink(digestfile);
        return set_err(err_msg, "pull: digestfile read failed", EIO);
    }
    fclose(f);
    unlink(digestfile);
    digest[strcspn(digest, "\r\n")] = '\0';
    if (strncmp(digest, "sha256:", 7) != 0)
        return set_err_fmt(err_msg, EPROTO,
                           "pull: unexpected digestfile contents '%s'", digest);

    /* Digest-pinned refs are self-describing; only tagged refs need the
     * name-to-digest pin.
     */
    if (!ref->tag)
        return 0;

    return oci_store_put_ref(store, ref, digest, err_msg);
}
