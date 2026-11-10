/*
 * Native-host unit test for the newline record splitter.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The signal transport drain reads its file in 8 KiB chunks and keeps one
 * splitter across them, so a record cut by a chunk end is finished by the next
 * chunk. A guest test cannot make one drain see more than a chunk, so this test
 * feeds the same input through one splitter at every chunk size and expects the
 * records that one whole read gives.
 */

#include <stdio.h>
#include <string.h>

#include "host-test-util.h"
#include "syscall/record-split.h"

typedef struct {
    char out[1024];
    size_t len;
} collect_t;

static void collect_cb(char *rec, void *vctx)
{
    collect_t *c = vctx;
    int n = snprintf(c->out + c->len, sizeof(c->out) - c->len, "[%s]", rec);
    if (n > 0 && (size_t) n < sizeof(c->out) - c->len)
        c->len += (size_t) n;
}

static void split_in_chunks(const char *in,
                            size_t n,
                            size_t chunk,
                            collect_t *c)
{
    record_splitter_t sp = {.len = 0};
    memset(c, 0, sizeof(*c));
    for (size_t off = 0; off < n; off += chunk) {
        size_t take = n - off < chunk ? n - off : chunk;
        record_split(&sp, in + off, take, collect_cb, c);
    }
}

int main(void)
{
    const char *lane = "records across chunks";
    char in[512];
    char overlong[200];
    memset(overlong, '9', sizeof(overlong) - 1);
    overlong[sizeof(overlong) - 1] = '\0';
    int n = snprintf(in, sizeof(in), "1 42 34\n2 42 35\n%s\n3 42 36\n\n4 42 37",
                     overlong);
    host_check(n > 0 && (size_t) n < sizeof(in), lane, "input fits");

    /* The 199-byte line is dropped, the empty line is a record, and the
     * unterminated tail is held back.
     */
    const char *want = "[1 42 34][2 42 35][3 42 36][]";
    collect_t got;
    for (size_t chunk = 1; chunk <= (size_t) n; chunk++) {
        split_in_chunks(in, (size_t) n, chunk, &got);
        if (strcmp(got.out, want) != 0) {
            char detail[160];
            snprintf(detail, sizeof(detail), "chunk %zu gave %.100s", chunk,
                     got.out);
            host_check(false, lane, detail);
            break;
        }
        host_ok();
    }

    /* The held-back tail is finished by the next read through the same
     * splitter, as a drain finishes a record cut by the previous chunk.
     */
    record_splitter_t sp = {.len = 0};
    memset(&got, 0, sizeof(got));
    record_split(&sp, "5 42 3", 6, collect_cb, &got);
    record_split(&sp, "8\n", 2, collect_cb, &got);
    host_check(strcmp(got.out, "[5 42 38]") == 0, "tail finished later",
               got.out);

    return host_summary("test-record-split-host");
}
