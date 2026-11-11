/*
 * Capabilities for Clang thread safety analysis
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The build passes -Wthread-safety, so a function declared REQUIRES(c) cannot
 * be called on a path that does not hold c, and the functions declared
 * ACQUIRE(c) and RELEASE(c) are the only ways a path gains or gives it up. The
 * check runs in the compiler on every build and covers only what carries these
 * annotations. See https://clang.llvm.org/docs/ThreadSafetyAnalysis.html.
 */

#pragma once

#if defined(__clang__)
#define ELFUSE_TSA(x) __attribute__((x))
#else
#define ELFUSE_TSA(x)
#endif

#define CAPABILITY(x) ELFUSE_TSA(capability(x))
#define REQUIRES(...) ELFUSE_TSA(requires_capability(__VA_ARGS__))
#define ACQUIRE(...) ELFUSE_TSA(acquire_capability(__VA_ARGS__))
#define RELEASE(...) ELFUSE_TSA(release_capability(__VA_ARGS__))
#define ASSERT_CAPABILITY(x) ELFUSE_TSA(assert_capability(x))

/* Opt a function out of the analysis. Every use carries a comment naming what
 * makes it safe, since the compiler no longer checks it.
 */
#define NO_THREAD_SAFETY_ANALYSIS ELFUSE_TSA(no_thread_safety_analysis)

/* A capability with no lock behind it: a role a thread holds between the
 * functions annotated to grant and revoke it. The object is never read.
 */
typedef struct CAPABILITY("role") {
    char unused;
} elfuse_role_t;
