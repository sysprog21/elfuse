#pragma once

#include "dispatch.h"

/* Name table generated from dispatch.tbl: shared with syscall.c so verbose
 * logs can print syscall names. A new entry in dispatch.tbl automatically
 * gains a name here; slots without a corresponding entry stay NULL and the
 * caller falls back to printing the raw number.
 */
static const char *const syscall_names[SC_MAX_SYSCALL_NUM + 1] = {
#define _(sys_name, sc_handler, extra) [sys_name] = #sys_name,
    SYSCALL_TABLE_ENTRIES(_)
#undef _
};

