/*
 * Move the unread tail of an append-only file to its front
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The signal transport is truncated only once a drain has read everything in
 * it. A sender that appends inside every drain window keeps that from
 * happening, so the drain compacts instead: file_compact() copies the bytes
 * from @off to @size to the start of the file and truncates it to their length.
 * The caller holds the lock every appender takes.
 */

#pragma once

#include <errno.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

/* Copy [@off, @size) of @fd to [0, @size - @off) through @buf, then truncate
 * @fd to @size - @off.
 *
 * Returns 0 on success, -1 with errno set on failure.
 *
 * The copy writes only below @off, so it refuses (EAGAIN) a tail longer than
 * @off: a copy that failed partway would otherwise have overwritten bytes it
 * had not yet read. On a failure the bytes from @off on are unchanged, so the
 * caller keeps reading at @off.
 */
static inline int file_compact(int fd,
                               off_t off,
                               off_t size,
                               char *buf,
                               size_t bufsz)
{
    if (off <= 0 || size < off || size - off > off) {
        errno = EAGAIN;
        return -1;
    }
    for (off_t pos = off; pos < size;) {
        size_t want = (size_t) (size - pos);
        if (want > bufsz)
            want = bufsz;
        ssize_t r;
        do
            r = pread(fd, buf, want, pos);
        while (r < 0 && errno == EINTR);
        if (r <= 0) {
            if (r == 0)
                errno = EIO;
            return -1;
        }
        for (ssize_t done = 0; done < r;) {
            ssize_t w;
            do
                w = pwrite(fd, buf + done, (size_t) (r - done),
                           pos - off + done);
            while (w < 0 && errno == EINTR);
            if (w <= 0) {
                if (w == 0)
                    errno = EIO;
                return -1;
            }
            done += w;
        }
        pos += r;
    }
    return ftruncate(fd, size - off);
}
