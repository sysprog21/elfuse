/* OCI layer applier implementation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oci/layer-apply.h"
#include "oci/util.h"

#define LA_PATH_MAX 4096
#define LA_CHUNK 65536

/* strchrnul is gated behind macOS 15.4 deployment target; emulate it
 * inline so the applier builds against older SDKs without an
 * availability check.
 */
static const char *la_strchrnul(const char *s, int c)
{
    const char *p = strchr(s, c);
    return p ? p : s + strlen(s);
}

static const char *basename_of(const char *p)
{
    const char *slash = strrchr(p, '/');
    return slash ? slash + 1 : p;
}

/* Normalize the parent prefix of guest_path into parent_out (without
 * trailing slash). parent_out may be the same buffer as guest_path's
 * substring source, but for safety the caller passes a fresh buffer.
 */
static void parent_of(const char *guest_path, char *parent_out, size_t cap)
{
    const char *slash = strrchr(guest_path, '/');
    if (!slash) {
        parent_out[0] = '\0';
        return;
    }
    size_t n = (size_t) (slash - guest_path);
    if (n >= cap)
        n = cap - 1;
    memcpy(parent_out, guest_path, n);
    parent_out[n] = '\0';
}

int oci_path_join_safe(const char *root_dir,
                       const char *guest_path,
                       char *out,
                       size_t cap,
                       const char **err)
{
    if (!root_dir || !guest_path || !out || cap == 0)
        return set_err(err, "path join: NULL argument", EINVAL);
    if (guest_path[0] == '/')
        return set_err(err, "path join: absolute guest path", EINVAL);
    if (guest_path[0] == '\0' || strcmp(guest_path, ".") == 0)
        return set_err(err, "path join: empty path", EINVAL);

    /* Walk segments and reject `..` outright. Mirrors the no-follow
     * basename rule from src/syscall/path.h::path_translate_at.
     */
    const char *p = guest_path;
    while (*p) {
        const char *next = la_strchrnul(p, '/');
        size_t seglen = (size_t) (next - p);
        if (seglen == 2 && p[0] == '.' && p[1] == '.')
            return set_err(err, "path join: segment is ..", EINVAL);
        p = *next ? next + 1 : next;
    }

    size_t rl = strlen(root_dir);
    size_t gl = strlen(guest_path);
    if (rl + 1 + gl + 1 > cap)
        return set_err(err, "path join: assembled length overflow",
                       ENAMETOOLONG);
    memcpy(out, root_dir, rl);
    out[rl] = '/';
    memcpy(out + rl + 1, guest_path, gl + 1);
    return 0;
}

int oci_symlink_target_check(const char *link_dir, const char *target)
{
    if (!target)
        return set_err(NULL, NULL, EINVAL);

    /* Compose the conceptual destination relative to the unpack root.
     * Absolute targets treat '/' as the unpack root (the symlink is
     * unpacked into the layer sysroot, so absolute means root-relative);
     * relative targets start from link_dir.
     */
    char buf[LA_PATH_MAX];
    if (target[0] == '/') {
        if (strlcpy(buf, target + 1, sizeof(buf)) >= sizeof(buf))
            return set_err(NULL, NULL, ENAMETOOLONG);
    } else {
        if (link_dir && link_dir[0]) {
            if ((size_t) snprintf(buf, sizeof(buf), "%s/%s", link_dir,
                                  target) >= sizeof(buf))
                return set_err(NULL, NULL, ENAMETOOLONG);
        } else {
            if (strlcpy(buf, target, sizeof(buf)) >= sizeof(buf))
                return set_err(NULL, NULL, ENAMETOOLONG);
        }
    }

    /* Track depth as we walk segments. `..` decrements; `.` and empty
     * stay. Any drop below zero means a follower would step above the
     * unpack root, which is rejected.
     */
    int depth = 0;
    char *save = NULL;
    char *seg = strtok_r(buf, "/", &save);
    while (seg) {
        if (strcmp(seg, "..") == 0) {
            if (--depth < 0)
                return set_err(NULL, NULL, ELOOP);
        } else if (strcmp(seg, ".") != 0 && seg[0] != '\0') {
            depth++;
        }
        seg = strtok_r(NULL, "/", &save);
    }
    return 0;
}

/* Walk guest_path's parent chain from root_fd one segment at a time,
 * refusing to traverse any component that is not a real directory:
 * openat with O_NOFOLLOW | O_DIRECTORY fails on a symlink (ELOOP) or a
 * regular file (ENOTDIR). The lexical checks in oci_path_join_safe and
 * oci_symlink_target_check cannot stop a symlink written by an earlier
 * tar entry from redirecting a later entry's parent chain outside the
 * unpack root, so containment is enforced physically here. `..` and
 * absolute paths are still rejected lexically: the walk is purely
 * descending.
 *
 * When create is true, missing components are mkdirat'ed (mode 0755;
 * the entry's own mode is applied later when the tar provides it).
 * When create is false, a missing component reports success with
 * *out_fd = -1 so removal-driven callers can treat an absent parent
 * as nothing-to-do.
 *
 * On success the final path component is copied into base_out and the
 * parent dirfd is written to *out_fd (caller closes). Returns 0 on
 * success, -1 with *err / errno set on failure.
 */
static int open_parent_at(int root_fd,
                          const char *guest_path,
                          bool create,
                          char *base_out,
                          size_t base_cap,
                          int *out_fd,
                          const char **err)
{
    *out_fd = -1;
    if (guest_path[0] == '/')
        return set_err(err, "layer apply: absolute guest path", EINVAL);

    char buf[LA_PATH_MAX];
    if (strlcpy(buf, guest_path, sizeof(buf)) >= sizeof(buf))
        return set_err(err, "layer apply: path overflow", ENAMETOOLONG);

    /* Directory entries may carry a trailing slash; drop it so the
     * final component below is the directory name itself.
     */
    size_t len = strlen(buf);
    while (len > 0 && buf[len - 1] == '/')
        buf[--len] = '\0';
    if (len == 0 || strcmp(buf, ".") == 0)
        return set_err(err, "layer apply: empty path", EINVAL);

    int fd = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (fd < 0)
        return set_err(err, "layer apply: dup root fd failed", errno);

    char *seg = buf;
    for (;;) {
        char *slash = strchr(seg, '/');
        if (!slash)
            break; /* seg is now the final component */
        *slash = '\0';
        if (strcmp(seg, "..") == 0) {
            close(fd);
            return set_err(err, "layer apply: segment is ..", EINVAL);
        }
        /* Empty ("a//b") and "." segments add nothing to the walk. */
        if (seg[0] != '\0' && strcmp(seg, ".") != 0) {
            if (create && mkdirat(fd, seg, 0755) < 0 && errno != EEXIST) {
                close(fd);
                return set_err(err, "layer apply: mkdir parent failed", errno);
            }
            int nfd = openat(fd, seg,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (nfd < 0) {
                int saved = errno;
                close(fd);
                if (!create && saved == ENOENT)
                    return 0; /* absent parent: *out_fd stays -1 */
                return set_err(
                    err, "layer apply: parent component is not a directory",
                    saved);
            }
            close(fd);
            fd = nfd;
        }
        seg = slash + 1;
    }
    if (strcmp(seg, "..") == 0) {
        close(fd);
        return set_err(err, "layer apply: segment is ..", EINVAL);
    }
    if (seg[0] == '\0' || strcmp(seg, ".") == 0) {
        close(fd);
        return set_err(err, "layer apply: empty final component", EINVAL);
    }
    if (strlcpy(base_out, seg, base_cap) >= base_cap) {
        close(fd);
        return set_err(err, "layer apply: component overflow", ENAMETOOLONG);
    }
    *out_fd = fd;
    return 0;
}

static int copy_payload_to_fd(oci_tar_reader_t *r,
                              int fd,
                              uint64_t want,
                              const char **err)
{
    uint8_t buf[LA_CHUNK];
    while (want > 0) {
        size_t got = 0;
        size_t take = want > sizeof(buf) ? sizeof(buf) : (size_t) want;
        const char *terr = NULL;
        if (oci_tar_read_payload(r, buf, take, &got, &terr) < 0)
            return set_err(err, terr ? terr : "tar payload read failed", EIO);
        if (got == 0)
            return set_err(err, "tar payload truncated", EIO);
        const uint8_t *p = buf;
        size_t remaining = got;
        while (remaining > 0) {
            ssize_t n = write(fd, p, remaining);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                return set_err(err, "layer apply: file write failed", errno);
            }
            p += n;
            remaining -= (size_t) n;
        }
        want -= got;
    }
    return 0;
}

static int apply_regular(oci_tar_reader_t *r,
                         const oci_tar_entry_t *e,
                         int dirfd,
                         const char *base,
                         oci_layer_apply_stats_t *stats,
                         const char **err)
{
    /* Remove any existing entry first so we never accidentally write
     * through a symlink left by a lower layer.
     */
    if (oci_rm_recursive_at(dirfd, base) < 0)
        return set_err(err, "layer apply: cannot remove existing entry", errno);
    int fd = openat(dirfd, base,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0)
        return set_err(err, "layer apply: open file failed", errno);
    if (copy_payload_to_fd(r, fd, e->size, err) < 0) {
        close(fd);
        (void) unlinkat(dirfd, base, 0);
        return -1;
    }
    /* fchmod to the requested mode bits (low 12). The host inode may
     * silently drop bits the running user cannot set, but the sidecar
     * carries the authoritative value regardless.
     */
    if (fchmod(fd, (mode_t) (e->mode & 07777)) < 0 && errno != EPERM)
        return set_err(err, "layer apply: fchmod failed", errno);
    close(fd);
    if (stats)
        stats->files++;
    return 0;
}

static int apply_dir(const oci_tar_entry_t *e,
                     int dirfd,
                     const char *base,
                     oci_layer_apply_stats_t *stats,
                     const char **err)
{
    if (mkdirat(dirfd, base, 0755) < 0) {
        if (errno != EEXIST)
            return set_err(err, "layer apply: mkdir failed", errno);
        /* An existing non-directory (file or symlink from a lower
         * layer) must give way to a real directory: children of this
         * entry refuse to traverse symlink components, and overlay
         * semantics let an upper directory shadow a lower entry.
         */
        struct stat st;
        if (fstatat(dirfd, base, &st, AT_SYMLINK_NOFOLLOW) < 0)
            return set_err(err, "layer apply: stat existing entry failed",
                           errno);
        if (!S_ISDIR(st.st_mode)) {
            if (oci_rm_recursive_at(dirfd, base) < 0 ||
                mkdirat(dirfd, base, 0755) < 0)
                return set_err(
                    err, "layer apply: replace entry with dir failed", errno);
        }
    }
    /* Apply mode bits via an O_NOFOLLOW + O_DIRECTORY fd so a racing
     * swap to a symlink cannot redirect the chmod.
     */
    int fd =
        openat(dirfd, base, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        (void) fchmod(fd, (mode_t) (e->mode & 07777));
        close(fd);
    }
    if (stats)
        stats->dirs++;
    return 0;
}

/* Cap on path components for the symlink-target rewrite below. Tar entry
 * names are already length-checked against LA_PATH_MAX; 256 components is
 * far beyond any real image layout and bounds the pointer arrays.
 */
#define LA_MAX_COMPONENTS 256

/* Rewrite an absolute symlink target into the equivalent path relative to
 * the link's own directory. Linux images routinely carry absolute applet
 * links (/bin/sh -> /bin/busybox); stored verbatim on the host they
 * resolve against the HOST root -- dangling at best, aliasing a host
 * binary at worst -- because no chroot confines the unpacked tree. The
 * relative spelling keeps resolution inside the rootfs for both the
 * pre-launch resolver and every in-guest openat/execve the host kernel
 * serves. Costs readlink(2) fidelity (the guest sees the rewritten
 * spelling), the same trade sys_symlinkat makes for guest-created links.
 *
 * link_parent is the link's guest directory as produced by parent_of ("",
 * no leading '/'); target starts with '/'. The caller has already run
 * oci_symlink_target_check, so ".." segments cannot climb above the
 * unpack root; they are folded lexically here.
 */
static int abs_target_to_relative(const char *link_parent,
                                  const char *target,
                                  char *out,
                                  size_t out_sz)
{
    char norm[LA_PATH_MAX];
    if (strlcpy(norm, target + 1, sizeof(norm)) >= sizeof(norm))
        return -1;
    const char *comp[LA_MAX_COMPONENTS];
    int ncomp = 0;
    char *save = NULL;
    for (char *seg = strtok_r(norm, "/", &save); seg;
         seg = strtok_r(NULL, "/", &save)) {
        if (!strcmp(seg, "."))
            continue;
        if (!strcmp(seg, "..")) {
            if (ncomp > 0)
                ncomp--;
            continue;
        }
        if (ncomp >= LA_MAX_COMPONENTS)
            return -1;
        comp[ncomp++] = seg;
    }

    char par[LA_PATH_MAX];
    if (strlcpy(par, link_parent ? link_parent : "", sizeof(par)) >=
        sizeof(par))
        return -1;
    const char *pcomp[LA_MAX_COMPONENTS];
    int npar = 0;
    save = NULL;
    for (char *seg = strtok_r(par, "/", &save); seg;
         seg = strtok_r(NULL, "/", &save)) {
        if (npar >= LA_MAX_COMPONENTS)
            return -1;
        pcomp[npar++] = seg;
    }

    int common = 0;
    while (common < npar && common < ncomp &&
           !strcmp(pcomp[common], comp[common]))
        common++;

    size_t pos = 0;
    for (int i = common; i < npar; i++) {
        if (pos + 3 >= out_sz)
            return -1;
        memcpy(out + pos, "../", 3);
        pos += 3;
    }
    for (int i = common; i < ncomp; i++) {
        size_t sl = strlen(comp[i]);
        if (pos + sl + 1 >= out_sz)
            return -1;
        memcpy(out + pos, comp[i], sl);
        pos += sl;
        out[pos++] = '/';
    }
    if (pos > 0 && out[pos - 1] == '/')
        pos--;
    if (pos == 0) {
        if (out_sz < 2)
            return -1;
        out[pos++] = '.';
    }
    out[pos] = '\0';
    return 0;
}

static int apply_symlink(const oci_tar_entry_t *e,
                         int dirfd,
                         const char *base,
                         const char *guest_path,
                         oci_layer_apply_stats_t *stats,
                         const char **err)
{
    if (!e->linkname || !e->linkname[0])
        return set_err(err, "layer apply: empty symlink target", EINVAL);

    char parent[LA_PATH_MAX];
    parent_of(guest_path, parent, sizeof(parent));
    if (oci_symlink_target_check(parent, e->linkname) < 0)
        return set_err(err, "layer apply: symlink target escapes root", ELOOP);

    const char *link_target = e->linkname;
    char rel_buf[LA_PATH_MAX];
    if (link_target[0] == '/') {
        if (abs_target_to_relative(parent, link_target, rel_buf,
                                   sizeof(rel_buf)) < 0)
            return set_err(err, "layer apply: symlink target too long",
                           ENAMETOOLONG);
        link_target = rel_buf;
    }

    if (oci_rm_recursive_at(dirfd, base) < 0)
        return set_err(err, "layer apply: cannot remove existing entry", errno);
    if (symlinkat(link_target, dirfd, base) < 0)
        return set_err(err, "layer apply: symlink failed", errno);
    if (stats)
        stats->symlinks++;
    return 0;
}

static int apply_hardlink(const oci_tar_entry_t *e,
                          int root_fd,
                          int dirfd,
                          const char *base,
                          oci_layer_apply_stats_t *stats,
                          const char **err)
{
    if (!e->linkname || !e->linkname[0])
        return set_err(err, "layer apply: empty hardlink target", EINVAL);

    /* The hardlink target is an intra-archive guest path. Resolve it
     * through the same descending no-follow walk as entry paths so a
     * symlinked component cannot pull a host file into the tree.
     */
    char tbase[LA_PATH_MAX];
    int tfd = -1;
    if (open_parent_at(root_fd, e->linkname, false, tbase, sizeof(tbase), &tfd,
                       err) < 0)
        return -1;
    /* The target must exist already; OCI mandates entries in apply
     * order, and a hardlink that names a missing file is a malformed
     * archive (or a forward reference, which we explicitly reject).
     */
    if (tfd < 0)
        return set_err(err, "layer apply: hardlink target missing", ENOLINK);
    struct stat st;
    if (fstatat(tfd, tbase, &st, AT_SYMLINK_NOFOLLOW) < 0) {
        close(tfd);
        return set_err(err, "layer apply: hardlink target missing", ENOLINK);
    }

    if (oci_rm_recursive_at(dirfd, base) < 0) {
        close(tfd);
        return set_err(err, "layer apply: cannot remove existing entry", errno);
    }
    if (linkat(tfd, tbase, dirfd, base, 0) < 0) {
        close(tfd);
        return set_err(err, "layer apply: link failed", errno);
    }
    close(tfd);
    if (stats)
        stats->hardlinks++;
    return 0;
}

static int apply_whiteout(const oci_tar_entry_t *e,
                          int root_fd,
                          oci_meta_table_t *meta,
                          oci_layer_apply_stats_t *stats,
                          const char **err)
{
    /* Path is "...dir/.wh.<name>"; the entry being whited out is
     * "...dir/<name>".
     */
    const char *base = basename_of(e->path);
    if (strncmp(base, ".wh.", 4) != 0 || base[4] == '\0')
        return set_err(err, "layer apply: malformed whiteout entry", EINVAL);

    size_t parent_len = (size_t) (base - e->path);
    char target[LA_PATH_MAX];
    if (parent_len + strlen(base + 4) + 1 > sizeof(target))
        return set_err(err, "layer apply: whiteout path overflow",
                       ENAMETOOLONG);
    memcpy(target, e->path, parent_len);
    snprintf(target + parent_len, sizeof(target) - parent_len, "%s", base + 4);

    char tname[LA_PATH_MAX];
    int dfd = -1;
    if (open_parent_at(root_fd, target, false, tname, sizeof(tname), &dfd,
                       err) < 0)
        return -1;
    if (dfd >= 0) {
        /* An absent parent chain (dfd == -1) means there is nothing to
         * remove; oci_rm_recursive_at already treats a missing entry
         * as success.
         */
        if (oci_rm_recursive_at(dfd, tname) < 0) {
            close(dfd);
            return set_err(err, "layer apply: whiteout removal failed", errno);
        }
        close(dfd);
    }
    if (meta)
        oci_meta_remove(meta, target);
    if (stats)
        stats->whiteouts++;
    return 0;
}

static int apply_opaque_whiteout(const oci_tar_entry_t *e,
                                 int root_fd,
                                 oci_meta_table_t *meta,
                                 oci_layer_apply_stats_t *stats,
                                 const char **err)
{
    /* Path is "...dir/.wh..wh..opq"; clear all CHILDREN of "...dir/"
     * but leave the directory itself.
     */
    const char *base = basename_of(e->path);
    if (strcmp(base, ".wh..wh..opq") != 0)
        return set_err(err, "layer apply: malformed opaque marker", EINVAL);
    size_t parent_len = (size_t) (base - e->path);
    char dir[LA_PATH_MAX];
    if (parent_len == 0) {
        /* Opaque at layer root: clear top-level lower-layer entries. */
        dir[0] = '\0';
    } else {
        /* Drop the trailing slash before the marker. */
        size_t copy = parent_len - 1;
        if (copy + 1 > sizeof(dir))
            return set_err(err, "layer apply: opaque path overflow",
                           ENAMETOOLONG);
        memcpy(dir, e->path, copy);
        dir[copy] = '\0';
    }

    int dfd;
    if (dir[0] == '\0') {
        dfd = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
        if (dfd < 0)
            return set_err(err, "layer apply: dup root fd failed", errno);
    } else {
        char dbase[LA_PATH_MAX];
        int pfd = -1;
        if (open_parent_at(root_fd, dir, false, dbase, sizeof(dbase), &pfd,
                           err) < 0)
            return -1;
        if (pfd < 0) {
            /* Absent parent chain: nothing to clear. */
            if (stats)
                stats->opaques++;
            return 0;
        }
        dfd =
            openat(pfd, dbase, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int saved = errno;
        close(pfd);
        if (dfd < 0) {
            if (saved == ENOENT) {
                if (stats)
                    stats->opaques++;
                return 0;
            }
            return set_err(err, "layer apply: opaque opendir failed", saved);
        }
    }

    DIR *d = fdopendir(dfd);
    if (!d) {
        close(dfd);
        return set_err(err, "layer apply: opaque opendir failed", errno);
    }
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (strncmp(de->d_name, ".wh.", 4) == 0)
            continue; /* let the marker entry itself stay for the iter */
        if (oci_rm_recursive_at(dfd, de->d_name) < 0) {
            rc = -1;
            break;
        }
        if (meta) {
            char child_guest[LA_PATH_MAX];
            if (dir[0])
                snprintf(child_guest, sizeof(child_guest), "%s/%s", dir,
                         de->d_name);
            else
                snprintf(child_guest, sizeof(child_guest), "%s", de->d_name);
            oci_meta_remove(meta, child_guest);
        }
    }
    closedir(d);
    if (rc < 0)
        return set_err(err, "layer apply: opaque clear failed", errno);
    if (stats)
        stats->opaques++;
    return 0;
}

/* Whiteout-handling discipline shared by oci_layer_apply (overlay) and
 * oci_layer_apply_raw_tar (raw per-layer cache populate).
 * Overlay mode interprets .wh.<name> and .wh..wh..opq tar entries as
 * delete / clear directives against root_dir; raw mode leaves them as
 * regular 0-byte files at their tar path so the assembler can replay
 * the whiteout intent against the running work_dir later.
 */
typedef enum {
    APPLY_MODE_OVERLAY,
    APPLY_MODE_RAW_TAR,
} apply_mode_t;

static int layer_apply_loop(oci_tar_reader_t *r,
                            int root_fd,
                            apply_mode_t mode,
                            oci_layer_apply_stats_t *stats,
                            oci_meta_table_t *meta,
                            const char **err)
{
    for (;;) {
        oci_tar_entry_t e;
        const char *terr = NULL;
        int rc = oci_tar_next(r, &e, &terr);
        if (rc < 0)
            return set_err(err, terr ? terr : "tar next failed",
                           errno ? errno : EIO);
        if (rc == 0)
            return 0;

        /* Strip a leading slash if present; OCI layer paths are
         * relative, but some encoders ship them with a leading slash.
         */
        const char *gp = e.path;
        while (gp[0] == '/')
            gp++;

        /* Root-directory tar entry: docker/buildkit emit "./" as the
         * first entry of a layer; the DIR-type trailing-slash strip
         * upstream collapses it to ".". The unpack root already
         * exists by the time the assembler enters this loop, so the
         * root entry has no work to drive. Skip empty paths the same
         * way for archives that record a zero-length root name.
         */
        if (gp[0] == '\0' || (gp[0] == '.' && gp[1] == '\0'))
            continue;

        if (mode == APPLY_MODE_OVERLAY) {
            if (e.is_opaque_whiteout) {
                oci_tar_entry_t e2 = e;
                e2.path = gp;
                if (apply_opaque_whiteout(&e2, root_fd, meta, stats, err) < 0)
                    return -1;
                continue;
            }
            if (e.is_whiteout) {
                oci_tar_entry_t e2 = e;
                e2.path = gp;
                if (apply_whiteout(&e2, root_fd, meta, stats, err) < 0)
                    return -1;
                continue;
            }
        }
        /* Raw-tar mode falls through: .wh.<name> and .wh..wh..opq are
         * typeflag '0' regular tar entries with zero payload, and the
         * regular-file dispatch below writes them on disk as 0-byte
         * files at their tar path. The assembler consumes the markers
         * later.
         */

        if (e.type == OCI_TAR_UNSUPPORTED)
            return set_err(err, "layer apply: unsupported entry type", ENOTSUP);

        char base[LA_PATH_MAX];
        int dirfd = -1;
        if (open_parent_at(root_fd, gp, true, base, sizeof(base), &dirfd, err) <
            0)
            return -1;

        oci_tar_entry_t e2 = e;
        e2.path = gp;
        int arc = 0;
        switch (e.type) {
        case OCI_TAR_REG:
            arc = apply_regular(r, &e2, dirfd, base, stats, err);
            break;
        case OCI_TAR_DIR:
            arc = apply_dir(&e2, dirfd, base, stats, err);
            break;
        case OCI_TAR_SYMLINK:
            arc = apply_symlink(&e2, dirfd, base, gp, stats, err);
            break;
        case OCI_TAR_HARDLINK:
            arc = apply_hardlink(&e2, root_fd, dirfd, base, stats, err);
            break;
        case OCI_TAR_UNSUPPORTED:
            /* Already handled above; here for switch completeness. */
            arc = set_err(err, "layer apply: unsupported entry type", ENOTSUP);
            break;
        }
        close(dirfd);
        if (arc < 0)
            return -1;

        if (meta && e.type != OCI_TAR_HARDLINK)
            (void) oci_meta_record(meta, gp, e.uid, e.gid, e.mode);
    }
}

static int layer_apply_impl(oci_tar_reader_t *r,
                            const char *root_dir,
                            apply_mode_t mode,
                            oci_layer_apply_stats_t *stats,
                            oci_meta_table_t *meta,
                            const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!r || !root_dir)
        return set_err(err, "layer apply: NULL argument", EINVAL);

    /* Anchor the whole apply on a dirfd of the unpack root; every path
     * below it is then resolved one component at a time with
     * O_NOFOLLOW so tar content can never steer a write through a
     * symlink it planted earlier.
     */
    int root_fd = open(root_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        return set_err(err, "layer apply: open root failed", errno);
    int rc = layer_apply_loop(r, root_fd, mode, stats, meta, err);
    close(root_fd);
    return rc;
}

int oci_layer_apply(oci_tar_reader_t *r,
                    const char *root_dir,
                    oci_layer_apply_stats_t *stats,
                    oci_meta_table_t *meta,
                    const char **err)
{
    return layer_apply_impl(r, root_dir, APPLY_MODE_OVERLAY, stats, meta, err);
}

int oci_layer_apply_raw_tar(oci_tar_reader_t *r,
                            const char *root_dir,
                            oci_layer_apply_stats_t *stats,
                            oci_meta_table_t *meta,
                            const char **err)
{
    return layer_apply_impl(r, root_dir, APPLY_MODE_RAW_TAR, stats, meta, err);
}
