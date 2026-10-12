/*
 * Linux ABI size limits
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split out of syscall/internal.h so a file that only needs a Linux ABI limit
 * for buffer sizing (core/bootstrap.h, core/sysroot.h) does not have to pull in
 * internal.h's cross-module locks and FD table declarations to get it.
 *
 * At src/ root rather than under syscall/ for the same reason one step on: a
 * constant the Linux ABI fixes belongs to no layer, and core/ reaching into
 * syscall/ to read one made the include graph say the two are coupled when only
 * a number passes between them.
 */

#pragma once

/* Linux PATH_MAX (4096): used for path buffer sizing in syscall handlers. The
 * literal 4096 in core/stack.c (the AT_PAGESZ auxv entry) means actual page
 * size, not this.
 */
#define LINUX_PATH_MAX 4096

/* Smallest sigaltstack Linux aarch64 accepts, and what AT_MINSIGSTKSZ reports.
 * sys_sigaltstack rejects anything below it, so the auxv value and the check
 * have to be the same number.
 */
#define LINUX_MINSIGSTKSZ 5120

/* execve argument limits.
 *
 * LINUX_MAX_ARG_STRLEN is the kernel's MAX_ARG_STRLEN, 32 pages on a 4 KiB
 * kernel. LINUX_ARG_MAX and LINUX_ARG_BYTES_CEILING bound what
 * bprm_stack_limits (fs/exec.c) lets the strings and their pointers take, a
 * quarter of RLIMIT_STACK held between the two: ARG_MAX, and three quarters of
 * _STK_LIM, the 8 MiB default stack. ELFUSE_MAX_ARG_STRINGS is elfuse's own
 * cap, chosen so a guest cannot drive an unbounded host allocation; it shares
 * MAX_ARG_STRLEN's value by coincidence, not by derivation, which is why it is
 * named separately.
 *
 * Shared rather than per-file: read_string_array (src/syscall/exec.c) enforces
 * the count while building the arrays, build_linux_stack (src/core/stack.c)
 * enforces it again while pushing them, and src/proved/stack.h states the
 * containment argument for STACK_MAX_WORDS in terms of it. Three copies of the
 * number let a change to one leave the other two disagreeing in silence.
 */
#define LINUX_MAX_ARG_STRLEN 131072
#define LINUX_ARG_MAX 131072
#define LINUX_ARG_BYTES_CEILING (6 * 1024 * 1024)
#define ELFUSE_MAX_ARG_STRINGS 131072
