/*
 * System info and identity syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Uname, getrandom, getcwd, sched_getaffinity, getgroups, getrusage, sysinfo,
 * and prlimit64. System queries that do not fit neatly into filesystem, I/O, or
 * time categories.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/guest.h"
#include "syscall/linux-wire.h"

/* Guest-visible kernel identity for uname(2) and /proc/version;
 * tests/test-proc.c pins the two surfaces to each other. The release names the
 * 6.18 LTS baseline and tracks no test image; syscall/dispatch.tbl states what
 * elfuse implements. glibc rejects only a release below its build-time floor,
 * so a high floor is the safe side.
 */
#define GUEST_KERNEL_RELEASE "6.18.0"
#define GUEST_KERNEL_VERSION "#1 SMP PREEMPT_DYNAMIC"

/* System info syscall handlers. */

int64_t sys_uname(guest_t *g, uint64_t buf_gva);
int64_t sys_getrandom(guest_t *g,
                      uint64_t buf_gva,
                      uint64_t buflen,
                      unsigned int flags);
int64_t sys_getcwd(guest_t *g, uint64_t buf_gva, uint64_t size);
int64_t sys_getcpu(guest_t *g,
                   uint64_t cpu_gva,
                   uint64_t node_gva,
                   uint64_t cache_gva);
int64_t sys_sched_getaffinity(guest_t *g,
                              int pid,
                              uint64_t size,
                              uint64_t mask_gva);
int64_t sys_sched_getscheduler(int pid);
int64_t sys_sched_getparam(guest_t *g, int pid, uint64_t param_gva);
int64_t sys_sched_setscheduler(guest_t *g,
                               int pid,
                               int policy,
                               uint64_t param_gva);
int64_t sys_sched_setparam(guest_t *g, int pid, uint64_t param_gva);
int64_t sys_sched_get_priority_min(int policy);
int64_t sys_sched_get_priority_max(int policy);
int64_t sys_sched_rr_get_interval(guest_t *g, int pid, uint64_t ts_gva);
int64_t sys_getgroups(guest_t *g, int size, uint64_t list_gva);
int64_t sys_setgroups(guest_t *g, int size, uint64_t list_gva);
int64_t sys_getrusage(guest_t *g, int who, uint64_t usage_gva);
int64_t sys_sysinfo(guest_t *g, uint64_t info_gva);
int64_t sys_prlimit64(guest_t *g,
                      int pid,
                      int resource,
                      uint64_t new_gva,
                      uint64_t old_gva);

/* Guest-visible physical memory, shared by every surface that reports it.
 *
 * A guest that reads two surfaces subtracts one against the other, and there
 * the underflow happens beyond any saturating arithmetic elfuse does on its own
 * side. busybox free is exactly this reader: it takes total and free from
 * sysinfo(2) and buff/cache from /proc/meminfo, then computes used = total -
 * free - cached. So the total and the free both have to come from here rather
 * than being sampled once per surface.
 *
 * sys_guest_ram_bytes() is the total to report as MemTotal/totalram: the host's
 * real memory, or a plausible stand-in if the sysctl fails, never zero.
 * sys_guest_ram_free() is the matching free figure, taken from the same cached
 * snapshot sysinfo(2) reports and guaranteed not to exceed the total.
 */
uint64_t sys_guest_ram_bytes(void);
uint64_t sys_guest_ram_free(void);

/* Guest rlimit table, indexed by Linux resource number. It is guest state:
 * seeded from the host once, then read and written by prlimit64 with no host
 * setrlimit behind it. execve keeps the table because it keeps the process.
 */

/* Seed the table from host getrlimit. Called once by the process that boots the
 * guest.
 */
void sys_rlimit_init(void);

/* The fork boundary: the parent snapshots, the child checks the header copy
 * before trusting it and restores it in place of sys_rlimit_init.
 */
void sys_rlimit_snapshot(linux_rlimit64_t out[LINUX_RLIMIT_COUNT]);
bool sys_rlimit_table_valid(const linux_rlimit64_t in[LINUX_RLIMIT_COUNT]);
void sys_rlimit_restore(const linux_rlimit64_t in[LINUX_RLIMIT_COUNT]);

/* Soft limit of @resource, LINUX_RLIM_INFINITY when unlimited. Lock-free, for
 * the sites that enforce a limit.
 */
uint64_t sys_rlimit_cur(int resource);

/* Send SIGXFSZ for a request RLIMIT_FSIZE refused. Linux sends it to the thread
 * that made the request (send_sig to current), so it is queued for the calling
 * thread alone and a sibling that has it unblocked does not take it.
 */
void sys_rlimit_send_xfsz(void);

/* Format /proc/self/limits content into buf.
 *
 * Returns bytes written (excluding NUL) or -1 on error.
 */
int sys_format_limits(char *buf, size_t bufsz);
