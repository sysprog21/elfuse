/*
 * Time and timer syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Clock, nanosleep, gettimeofday, and interval timer operations. Translates
 * Linux clock IDs to macOS equivalents and emulates ITIMER_REAL internally.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "core/guest.h"
#include "syscall/linux-wire.h"

/* Return true when a guest-supplied timespec is well-formed: non-negative
 * seconds and a nanosecond field in [0, NSEC_PER_SEC). Mirrors the kernel
 * hrtimer validation shared by the timeout-bearing syscalls.
 */
bool linux_timespec_valid(const linux_timespec_t *ts);

/* Convert a validated guest timespec to a nanosecond count, saturating to
 * INT64_MAX on overflow rather than wrapping. A negative tv_sec yields 0.
 */
int64_t linux_timespec_to_ns_sat(const linux_timespec_t *ts);

/* Time/timer syscall handlers. */

int64_t sys_clock_getres(guest_t *g, int clockid, uint64_t tp_gva);
int64_t sys_clock_gettime(guest_t *g, int clockid, uint64_t tp_gva);
int64_t sys_nanosleep(guest_t *g, uint64_t req_gva, uint64_t rem_gva);
int64_t sys_clock_nanosleep(guest_t *g,
                            int clockid,
                            int flags,
                            uint64_t req_gva,
                            uint64_t rem_gva);
int64_t sys_gettimeofday(guest_t *g, uint64_t tv_gva, uint64_t tz_gva);
int64_t sys_times(guest_t *g, uint64_t buf_gva);
int64_t sys_setitimer(guest_t *g,
                      int which,
                      uint64_t new_gva,
                      uint64_t old_gva);
int64_t sys_getitimer(guest_t *g, int which, uint64_t val_gva);
int64_t sys_timer_create(guest_t *g,
                         int clockid,
                         uint64_t event_gva,
                         uint64_t id_gva);
int64_t sys_timer_gettime(guest_t *g, int id, uint64_t value_gva);
int64_t sys_timer_settime(guest_t *g,
                          int id,
                          int flags,
                          uint64_t value_gva,
                          uint64_t old_gva);
