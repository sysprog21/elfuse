/*
 * Runtime lock-order validator
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Built only by "make LOCKDEP=1", which force-includes this header into every
 * translation unit so the pthread lock calls below are routed through
 * src/debug/lockdep.c. The validator keeps a graph of which lock was held when
 * another was taken and fails on the acquisition that would close a cycle, on
 * one that runs against the order documented at the top of
 * src/syscall/internal.h, and on one taken while a documented leaf is held. A
 * single-threaded run of each path is enough: the two halves of an inversion
 * need not ever race, as in the Linux validator described in
 * Documentation/locking/lockdep-design.rst.
 */

#pragma once

#if defined(ELFUSE_LOCKDEP)

#include <pthread.h>

void lockdep_check(const void *lock,
                   const char *spelling,
                   const char *file,
                   int line);
void lockdep_push(const void *lock,
                  const char *spelling,
                  const char *file,
                  int line);
void lockdep_pop(const void *lock);
void lockdep_forget(const void *lock);

static inline int lockdep_mutex_lock(pthread_mutex_t *m,
                                     const char *spelling,
                                     const char *file,
                                     int line)
{
    lockdep_check(m, spelling, file, line);
    int rc = pthread_mutex_lock(m);
    if (rc == 0)
        lockdep_push(m, spelling, file, line);
    return rc;
}

/* A trylock cannot wait, so it cannot be half of a deadlock and adds no edge;
 * it is still held, so what is taken under it is checked against it.
 */
static inline int lockdep_mutex_trylock(pthread_mutex_t *m,
                                        const char *spelling,
                                        const char *file,
                                        int line)
{
    int rc = pthread_mutex_trylock(m);
    if (rc == 0)
        lockdep_push(m, spelling, file, line);
    return rc;
}

static inline int lockdep_mutex_unlock(pthread_mutex_t *m)
{
    lockdep_pop(m);
    return pthread_mutex_unlock(m);
}

static inline int lockdep_mutex_destroy(pthread_mutex_t *m)
{
    lockdep_forget(m);
    return pthread_mutex_destroy(m);
}

static inline int lockdep_rwlock_rdlock(pthread_rwlock_t *l,
                                        const char *spelling,
                                        const char *file,
                                        int line)
{
    lockdep_check(l, spelling, file, line);
    int rc = pthread_rwlock_rdlock(l);
    if (rc == 0)
        lockdep_push(l, spelling, file, line);
    return rc;
}

static inline int lockdep_rwlock_wrlock(pthread_rwlock_t *l,
                                        const char *spelling,
                                        const char *file,
                                        int line)
{
    lockdep_check(l, spelling, file, line);
    int rc = pthread_rwlock_wrlock(l);
    if (rc == 0)
        lockdep_push(l, spelling, file, line);
    return rc;
}

static inline int lockdep_rwlock_unlock(pthread_rwlock_t *l)
{
    lockdep_pop(l);
    return pthread_rwlock_unlock(l);
}

static inline int lockdep_rwlock_destroy(pthread_rwlock_t *l)
{
    lockdep_forget(l);
    return pthread_rwlock_destroy(l);
}

#define pthread_mutex_lock(m) lockdep_mutex_lock((m), #m, __FILE__, __LINE__)
#define pthread_mutex_trylock(m) \
    lockdep_mutex_trylock((m), #m, __FILE__, __LINE__)
#define pthread_mutex_unlock(m) lockdep_mutex_unlock(m)
#define pthread_mutex_destroy(m) lockdep_mutex_destroy(m)
#define pthread_rwlock_rdlock(l) \
    lockdep_rwlock_rdlock((l), #l, __FILE__, __LINE__)
#define pthread_rwlock_wrlock(l) \
    lockdep_rwlock_wrlock((l), #l, __FILE__, __LINE__)
#define pthread_rwlock_unlock(l) lockdep_rwlock_unlock(l)
#define pthread_rwlock_destroy(l) lockdep_rwlock_destroy(l)

#endif
