/*
 * Native-host unit test for the file tail compaction.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The signal transport drain compacts its file when a sender appends inside
 * every drain window. A guest test cannot keep a sender inside every window, so
 * this test runs file_compact() on a scratch file: the unread tail moves to the
 * front, a tail longer than the handled bytes is refused with the file left as
 * it was, and an O_APPEND writer lands after the moved tail.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "host-test-util.h"
#include "syscall/file-compact.h"

static char path[512];

static int fill(const char *data)
{
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    size_t n = strlen(data);
    if (write(fd, data, n) != (ssize_t) n) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool holds(int fd, const char *want)
{
    char buf[256];
    struct stat st;
    if (fstat(fd, &st) != 0 || (size_t) st.st_size != strlen(want) ||
        (size_t) st.st_size >= sizeof(buf))
        return false;
    ssize_t r = pread(fd, buf, (size_t) st.st_size, 0);
    return r == st.st_size && memcmp(buf, want, (size_t) r) == 0;
}

static void compact_case(const char *label,
                         const char *data,
                         off_t off,
                         size_t bufsz,
                         int want_rc,
                         const char *want)
{
    char buf[64];
    int fd = fill(data);
    if (fd < 0) {
        host_check(false, label, "cannot write the scratch file");
        return;
    }
    errno = 0;
    int rc = file_compact(fd, off, (off_t) strlen(data), buf, bufsz);
    host_check(rc == want_rc && (rc == 0 || errno == EAGAIN), label,
               "return value");
    host_check(holds(fd, want), label, "file contents");
    close(fd);
}

int main(int argc, char **argv)
{
    char root[512];
    if (host_scratch_root(argv[0], "file-compact", argc > 1 ? argv[1] : NULL,
                          root, sizeof(root)) != 0)
        return 1;
    int n = snprintf(path, sizeof(path), "%s/transport", root);
    if (n < 0 || (size_t) n >= sizeof(path)) {
        fprintf(stderr, "%s: scratch path too long: %s\n", argv[0], root);
        rmdir(root);
        return 1;
    }

    /* A 3-byte buffer makes the 7-byte tail take three copies. */
    compact_case("tail moved in pieces", "0123456789abcdefg", 10, 3, 0,
                 "abcdefg");
    compact_case("tail as long as the handled bytes", "01234567abcdefgh", 8, 64,
                 0, "abcdefgh");
    compact_case("nothing past the offset", "0123456789", 10, 64, 0, "");
    compact_case("tail longer than the handled bytes", "0123abcde", 4, 64, -1,
                 "0123abcde");
    compact_case("no handled bytes", "abc", 0, 64, -1, "abc");

    /* A sender that appends after the compaction lands after the moved tail. */
    int fd = fill("0123456789abc");
    char buf[64];
    int app = open(path, O_WRONLY | O_APPEND);
    host_check(fd >= 0 && app >= 0, "append after compaction", "open");
    if (fd >= 0 && app >= 0) {
        host_check(file_compact(fd, 10, 13, buf, sizeof(buf)) == 0,
                   "append after compaction", "compact");
        host_check(write(app, "de", 2) == 2, "append after compaction",
                   "append");
        host_check(holds(fd, "abcde"), "append after compaction",
                   "file contents");
    }
    if (app >= 0)
        close(app);
    if (fd >= 0)
        close(fd);

    unlink(path);
    rmdir(root);
    return host_summary("test-file-compact-host");
}
