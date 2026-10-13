/*
 * Held-lock count for the mmap_lock ordering checks
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Only a build with -DELFUSE_LOCK_ASSERT (make check-locks) sees this file: it
 * is force-included there, ahead of every source, and counts the pthread
 * mutexes and rwlocks the calling thread holds. The count answers one question,
 * whether this thread may block on mmap_lock, and is read by nothing but
 * assertions. It never decides whether a caller waits.
 *
 * mmap_lock and proc_tmpdir_lock rank at and above mmap_lock, so their own
 * sites call the pthread functions through a parenthesized name, which the
 * macros below do not match, and stay out of the count.
 */

#pragma once

#ifdef ELFUSE_LOCK_ASSERT

#include <pthread.h>

/* Weak, so the host unit tests that link a single object need no definition. */
__attribute__((weak)) _Thread_local unsigned lock_assert_held;

static inline int lock_assert_mutex_lock(pthread_mutex_t *m)
{
    int rc = pthread_mutex_lock(m);
    if (rc == 0)
        lock_assert_held++;
    return rc;
}

static inline int lock_assert_mutex_trylock(pthread_mutex_t *m)
{
    int rc = pthread_mutex_trylock(m);
    if (rc == 0)
        lock_assert_held++;
    return rc;
}

static inline int lock_assert_mutex_unlock(pthread_mutex_t *m)
{
    int rc = pthread_mutex_unlock(m);
    if (rc == 0)
        lock_assert_held--;
    return rc;
}

static inline int lock_assert_rwlock_rdlock(pthread_rwlock_t *l)
{
    int rc = pthread_rwlock_rdlock(l);
    if (rc == 0)
        lock_assert_held++;
    return rc;
}

static inline int lock_assert_rwlock_wrlock(pthread_rwlock_t *l)
{
    int rc = pthread_rwlock_wrlock(l);
    if (rc == 0)
        lock_assert_held++;
    return rc;
}

static inline int lock_assert_rwlock_unlock(pthread_rwlock_t *l)
{
    int rc = pthread_rwlock_unlock(l);
    if (rc == 0)
        lock_assert_held--;
    return rc;
}

#define pthread_mutex_lock(m) lock_assert_mutex_lock(m)
#define pthread_mutex_trylock(m) lock_assert_mutex_trylock(m)
#define pthread_mutex_unlock(m) lock_assert_mutex_unlock(m)
#define pthread_rwlock_rdlock(l) lock_assert_rwlock_rdlock(l)
#define pthread_rwlock_wrlock(l) lock_assert_rwlock_wrlock(l)
#define pthread_rwlock_unlock(l) lock_assert_rwlock_unlock(l)

#endif /* ELFUSE_LOCK_ASSERT */
