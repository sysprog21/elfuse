/*
 * Shared utility helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Small inline helpers and macros used across multiple modules. Keeps leaf
 * utilities in one place so they do not accumulate as single-function headers.
 */

#pragma once

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Align x up to the next multiple of a; a must be a power of two. Both x and a
 * are evaluated as uint64_t. Most callers manipulate guest addresses or sizes
 * that already fit, so this avoids surprises from signed/unsigned mixing in
 * alignment masks.
 */
#define ALIGN_UP(x, a) \
    (((uint64_t) (x) + ((uint64_t) (a) - 1)) & ~((uint64_t) (a) - 1))

/* Align x down to the previous multiple of a; a must be a power of two. */
#define ALIGN_DOWN(x, a) ((uint64_t) (x) & ~((uint64_t) (a) - 1))

/* The Linux ABI fixes the page size at 4KiB on aarch64 regardless of the host
 * page size, so this is shared by every guest memory path (mmap, brk, mprotect,
 * ELF loading).
 */
#define GUEST_PAGE_SIZE 4096ULL
#define PAGE_ALIGN_UP(x) ALIGN_UP(x, GUEST_PAGE_SIZE)

/* 2MiB block alignment shared by region setup, page table walking, and stack
 * placement. BLOCK_2MIB itself is defined in core/guest.h.
 */
#define ALIGN_2MIB_DOWN(x) ALIGN_DOWN(x, 2ULL * 1024 * 1024)
#define ALIGN_2MIB_UP(x) ALIGN_UP(x, 2ULL * 1024 * 1024)

/* Branchless range check: true when minx <= x < minx + size.
 *
 * Replaces the recurring pair (x >= minx && x < minx + size) with a single
 * unsigned compare: shift x into a [0, size) window and let unsigned wraparound
 * flag both underflow (x < minx) and overflow (x >= minx + size). Width-safe
 * for any operand up to uint64_t.
 *
 * Operands are cast to uint64_t *before* the subtraction so signed inputs near
 * the type extremes (e.g., LONG_MIN passed by a strtol result) cannot trigger
 * signed overflow UB. Negative signed values sign-extend through the unsigned
 * conversion to a large uint64_t, which still yields the correct out-of-range
 * answer.
 *
 * Caveat: x and minx are evaluated twice; do not pass expressions with side
 * effects.
 */
#define RANGE_CHECK(x, minx, size) \
    (((uint64_t) (x) - (uint64_t) (minx)) < (uint64_t) (size))

/* Number of elements in a fixed-size array. */
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#ifndef MIN
#define MIN(a, b)               \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a < _b ? _a : _b;      \
    })
#endif

#ifndef MAX
#define MAX(a, b)               \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a > _b ? _a : _b;      \
    })
#endif

/* Copy src into dst, truncating to dst_size-1 and always NUL-terminating.
 * Returns strlen(src) so the caller can detect truncation (ret >= dst_size).
 */
static inline size_t str_copy_trunc(char *dst, const char *src, size_t dst_size)
{
    size_t src_len = strlen(src);

    if (dst_size > 0) {
        size_t copy_len = src_len < dst_size ? src_len : dst_size - 1;
        memcpy(dst, src, copy_len);
        dst[copy_len] = '\0';
    }

    return src_len;
}

/* Free @n owned strings and the array holding them. Every slot must be a heap
 * copy, never a borrowed environ or argv pointer; a NULL @v is a no-op. The
 * count is a parameter rather than a NULL terminator because the guest argv
 * is counted rather than terminated.
 */
static inline void strv_free(const char **v, int n)
{
    if (!v)
        return;
    for (int i = 0; i < n; i++)
        free((void *) v[i]);
    free((void *) v);
}

/* close(2) on a cleanup path: preserves errno across the close so the caller's
 * failure errno survives untouched. Skips the close when fd < 0.
 */
static inline void close_keep_errno(int fd)
{
    int saved = errno;
    if (fd >= 0)
        (void) close(fd);
    errno = saved;
}

/* Encode @len bytes of @src as lowercase hex into @dst, writing len*2 hex
 * characters followed by a terminating NUL. @dst must hold at least len*2+1
 * bytes.
 *
 * Returns the number of hex characters written (len*2).
 */
static inline size_t bytes_to_hex(char *dst, const uint8_t *src, size_t len)
{
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        dst[i * 2] = hex_chars[(src[i] >> 4) & 0xf];
        dst[i * 2 + 1] = hex_chars[src[i] & 0xf];
    }
    dst[len * 2] = '\0';
    return len * 2;
}

/* Decode a single hex digit to its 0-15 value, or -1 if @c is not a hex digit.
 * The inverse building block of bytes_to_hex; accepts either case. The bounds
 * matter to callers that shift the result: "hex_nibble(c) << 4" is undefined
 * behavior when c is not a hex digit, so the range and the digit-or-not
 * equivalence are both stated for Frama-C (make verify-rsp).
 */
/*@ logic integer hex_val(integer c) =
      ('0' <= c <= '9')   ? c - '0' :
      ('a' <= c <= 'f')   ? c - 'a' + 10 :
      ('A' <= c <= 'F')   ? c - 'A' + 10 : -1;
 */
/*@
  assigns \nothing;
  ensures -1 <= \result <= 15;
  ensures \result >= 0 <==> (('0' <= c <= '9') || ('a' <= c <= 'f') ||
                             ('A' <= c <= 'F'));
  ensures \result == hex_val(c);
 */
static inline int hex_nibble(unsigned char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Write exactly @len bytes to a blocking @fd, resuming across short writes and
 * EINTR.
 *
 * Returns 0 once every byte is written, or -1 with errno set on error. An
 * unexpected zero-byte return is treated as EIO rather than spun on, since the
 * offset would otherwise never advance. A zero-length request returns 0.
 */
static inline int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, p + sent, len - sent);
        if (n > 0) {
            sent += (size_t) n;
            continue;
        }
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        errno = EIO;
        return -1;
    }
    return 0;
}

/* Read exactly @len bytes from a blocking @fd into @buf, resuming across short
 * reads and EINTR. On error returns -1 with errno set. On a premature EOF the
 * result depends on @eof_is_error: when true the call returns -1, when false it
 * returns the count of bytes read before EOF so the caller can detect a clean
 * end of stream. Otherwise returns @len.
 */
static inline ssize_t read_all(int fd, void *buf, size_t len, bool eof_is_error)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n > 0) {
            got += (size_t) n;
            continue;
        }
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (eof_is_error)
            return -1;
        break;
    }
    return (ssize_t) got;
}

/* Create a private per-user scratch directory. mkdir(path, 0700), then tolerate
 * an already-existing entry only if it is a real directory, owned by the
 * current uid, with no group/other access bits. That rejects a symlink, a
 * foreign-owned directory, or a stale world-writable one that a local user
 * could use to interpose on the contents. The group/other check matters because
 * an existing 0777 dir owned by this uid would otherwise pass and let other
 * local users drop files into it.
 *
 * Returns 0 on success, -1 with errno set (EACCES when the ownership, type, or
 * permission check fails). Centralized so every caller applies the same guard;
 * drift here is a security bug.
 */
static inline int create_private_dir(const char *path)
{
    if (mkdir(path, 0700) < 0 && errno != EEXIST)
        return -1;

    struct stat st;
    if (lstat(path, &st) < 0)
        return -1;
    if (!S_ISDIR(st.st_mode) || st.st_uid != getuid() ||
        (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

/* Enable an fd flag if it is not already set.
 *
 * Returns 0 on success or -1 with errno preserved from the failing fcntl call.
 */
static inline int fd_set_fd_flag(int fd, int flag)
{
    int flags = fcntl(fd, F_GETFD);

    if (flags < 0)
        return -1;
    if ((flags & flag) != 0)
        return 0;
    return fcntl(fd, F_SETFD, flags | flag);
}

/* Set or clear a file status flag such as O_NONBLOCK. */
static inline int fd_update_status_flag(int fd, int flag, bool enabled)
{
    int flags = fcntl(fd, F_GETFL);

    if (flags < 0)
        return -1;
    if (enabled)
        flags |= flag;
    else
        flags &= ~flag;
    return fcntl(fd, F_SETFL, flags);
}

static inline int fd_set_cloexec(int fd)
{
    return fd_set_fd_flag(fd, FD_CLOEXEC);
}

static inline int fd_set_nonblock(int fd)
{
    return fd_update_status_flag(fd, O_NONBLOCK, true);
}

/* Carry overflow/underflow between tv_nsec and tv_sec so the result is a
 * canonical timespec with 0 <= tv_nsec < 1e9. Uses div/mod (which truncate
 * toward zero in C99) plus a single borrow so the LONG_MIN case never negates
 * tv_nsec -- that would be undefined behavior.
 *
 * NSEC_PER_SEC is also defined by mach/clock_types.h and dispatch/time.h on
 * macOS; the guard avoids redefinition warnings when those system headers are
 * pulled in transitively.
 */
#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000L
#endif

static inline void timespec_normalize(struct timespec *ts)
{
    ts->tv_sec += ts->tv_nsec / (long) NSEC_PER_SEC;
    ts->tv_nsec %= (long) NSEC_PER_SEC;
    if (ts->tv_nsec < 0) {
        ts->tv_sec -= 1;
        ts->tv_nsec += (long) NSEC_PER_SEC;
    }
}

/* Compute a CLOCK_REALTIME absolute deadline that is rel_ms milliseconds in the
 * future, suitable for pthread_cond_timedwait().
 */
static inline void timespec_deadline_in_ms(struct timespec *out, long rel_ms)
{
    clock_gettime(CLOCK_REALTIME, out);
    out->tv_sec += rel_ms / 1000;
    out->tv_nsec += (rel_ms % 1000) * 1000000L;
    timespec_normalize(out);
}

/* Bitmap helpers.
 *
 * Operate on a single uint64_t word. For multi-word bitmaps, callers index the
 * word and pass the bit position within it. Centralizing the shift and
 * compiler-intrinsic calls here keeps the meaning ("the bit for slot N",
 * "lowest set bit") visible at the call site instead of leaving readers to
 * decode 1ULL << (n) and __builtin_ctzll.
 */

/* The bit value for position n (0..63). n is evaluated once. */
#define BIT64(n) (1ULL << (n))

/* Mask of the low n bits. n may be 0..64. */
static inline uint64_t bit_mask64_low(unsigned int n)
{
    return n >= 64 ? UINT64_MAX : (BIT64(n) - 1);
}

/* Position of the lowest set bit. word must be non-zero -- __builtin_ctzll is
 * undefined on zero. Range: 0..63.
 */
static inline int bit_ctz64(uint64_t word)
{
    return __builtin_ctzll(word);
}

/* Number of set bits in word. */
static inline int bit_popcount64(uint64_t word)
{
    return __builtin_popcountll(word);
}

/* 64-bit FNV-1a over @len bytes. Not cryptographic: collision resistance is the
 * birthday bound on 64 bits, which suits stable identifiers derived from names
 * (synthetic inode numbers, derived filenames), not adversarial input.
 * Constants from the FNV reference (offset basis, prime).
 */
static inline uint64_t fnv1a64(const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *) data;
    uint64_t h = 1469598103934665603ULL;

    while (len--) {
        h ^= (uint64_t) *p++;
        h *= 1099511628211ULL;
    }
    return h;
}

/* Compiler attribute wrappers.
 *
 * PACKED removes inter-field padding, used for Linux ABI structures whose
 * layout must match the kernel exactly (e.g., linux_dirent64). Apply at the end
 * of a struct definition: } PACKED name_t;.
 */
#define PACKED __attribute__((packed))
