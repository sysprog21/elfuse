/*
 * Newline-terminated record splitter
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The lifecycle registry ("hostpid guestpid pgid startus") and the signal and
 * control transports hold bounded numeric lines, one record per line. Readers
 * take them in chunks of any size: record_split() keeps the start of a line cut
 * by a chunk end in the splitter and finishes it with the next chunk, so one
 * splitter has to live across every chunk of a read.
 *
 * The splitter keeps at most 159 bytes of a line and drops a longer line whole;
 * no writer emits one (a signal transport record is at most 63 bytes). An
 * unterminated tail stays in the splitter until a newline ends it. Every writer
 * appends a whole record under an exclusive lock, so a tail that never ends
 * only appears after a crash mid-write.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char line[160];
    size_t len;
    bool overlong;
} record_splitter_t;

/* Invoke @cb once per newline-terminated record in @data, passing a
 * NUL-terminated copy.
 */
static inline void record_split(record_splitter_t *sp,
                                const char *data,
                                size_t n,
                                void (*cb)(char *rec, void *ctx),
                                void *ctx)
{
    for (size_t i = 0; i < n; i++) {
        char c = data[i];
        if (c != '\n') {
            if (sp->len < sizeof(sp->line) - 1)
                sp->line[sp->len++] = c;
            else
                sp->overlong = true;
            continue;
        }
        if (!sp->overlong) {
            sp->line[sp->len] = '\0';
            cb(sp->line, ctx);
        }
        sp->len = 0;
        sp->overlong = false;
    }
}
