/* Shared helpers for the OCI subsystem (see util.h)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "util.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OCI_UTIL_PATH_MAX 4096

static _Thread_local char err_fmt_buf[2048];

void oci_err_static(const char **err, const char *msg)
{
    if (err)
        *err = msg;
}

void oci_err_fmt(const char **err, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err_fmt_buf, sizeof(err_fmt_buf), fmt, ap);
    va_end(ap);
    if (err)
        *err = err_fmt_buf;
}

static int mkdir_one(const char *path)
{
    if (mkdir(path, 0755) == 0)
        return 0;
    if (errno == EEXIST) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
            return 0;
        errno = ENOTDIR;
        return -1;
    }
    return -1;
}

int oci_mkdir_p(const char *path)
{
    char buf[OCI_UTIL_PATH_MAX];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(buf)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(buf, path, n + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir_one(buf) < 0)
            return -1;
        *p = '/';
    }
    return mkdir_one(buf);
}

int oci_rm_recursive(const char *path)
{
    struct stat st;
    if (lstat(path, &st) < 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return unlink(path);
    DIR *d = opendir(path);
    if (!d)
        return -1;
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char child[OCI_UTIL_PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        if (n < 0 || (size_t) n >= sizeof(child)) {
            errno = ENAMETOOLONG;
            rc = -1;
            break;
        }
        if (oci_rm_recursive(child) < 0) {
            rc = -1;
            break;
        }
    }
    closedir(d);
    if (rc == 0 && rmdir(path) < 0)
        rc = -1;
    return rc;
}

int oci_rm_recursive_at(int dirfd, const char *name)
{
    struct stat st;
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return unlinkat(dirfd, name, 0);
    int fd =
        openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    DIR *d = fdopendir(fd);
    if (!d) {
        close(fd);
        return -1;
    }
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (oci_rm_recursive_at(fd, de->d_name) < 0) {
            rc = -1;
            break;
        }
    }
    closedir(d);
    if (rc == 0 && unlinkat(dirfd, name, AT_REMOVEDIR) < 0)
        rc = -1;
    return rc;
}
