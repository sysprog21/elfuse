/*
 * Runtime lock-order validator
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * See src/debug/lockdep.h. A lock is identified by its address. One whose
 * spelling at the lock call names an entry of the order document takes that
 * entry's rank and kind; any other lock is an anonymous instance, checked for
 * cycles only. An edge h -> c is validated once, when it is first seen, so the
 * steady-state cost is a hash lookup per acquisition under one global lock.
 */

#if defined(ELFUSE_LOCKDEP)

#include <os/lock.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug/lockdep.h"

#include "lockdep-order.h"

#define LOCKDEP_MAX_CLASSES 4096
#define LOCKDEP_WORDS (LOCKDEP_MAX_CLASSES / 64)
#define LOCKDEP_ADDR_SLOTS 16384
#define LOCKDEP_EDGE_SLOTS 32768
#define LOCKDEP_MAX_HELD 32
#define LOCKDEP_NAME_MAX 64

/* Kinds, matching what scripts/check-lock-order.py emits into lockdep-order.h.
 * BOTTOM is log_mutex: the document lets any lock, leaves included, log while
 * held, so it sits below the whole order.
 */
enum {
    KIND_INSTANCE = 0,
    KIND_ORDERED = LOCKDEP_ORDERED,
    KIND_LEAF = LOCKDEP_LEAF,
    KIND_BOTTOM = LOCKDEP_BOTTOM,
};

typedef struct {
    const char *name;
    int kind;
    int rank;
} lockdep_doc_entry_t;

static const lockdep_doc_entry_t lockdep_doc[] = {LOCKDEP_DOC_ENTRIES};

typedef struct {
    bool used;
    int kind;
    int rank;
    char name[LOCKDEP_NAME_MAX];
} lock_class_t;

typedef struct {
    const void *key;
    int cls;
} addr_slot_t;

typedef struct {
    uint32_t key; /* (from + 1) << 16 | (to + 1), 0 when empty */
    const char *outer_file;
    int outer_line;
    const char *inner_file;
    int inner_line;
} edge_site_t;

typedef struct {
    const void *lock;
    int cls;
    const char *file;
    int line;
} held_t;

#define ADDR_TOMBSTONE ((const void *) 1)

static os_unfair_lock graph_lock = OS_UNFAIR_LOCK_INIT;
static lock_class_t classes[LOCKDEP_MAX_CLASSES];
static uint64_t adj[LOCKDEP_MAX_CLASSES][LOCKDEP_WORDS];
static addr_slot_t addr_map[LOCKDEP_ADDR_SLOTS];
static edge_site_t edge_sites[LOCKDEP_EDGE_SLOTS];
static int free_ids[LOCKDEP_MAX_CLASSES];
static int free_count;
static int next_id;
static bool exhausted_reported;

static _Thread_local held_t held[LOCKDEP_MAX_HELD];
static _Thread_local int held_depth;

static size_t addr_hash(const void *p)
{
    uintptr_t x = (uintptr_t) p;
    x ^= x >> 17;
    x *= 0xed5ad4bbU;
    x ^= x >> 11;
    return (size_t) x & (LOCKDEP_ADDR_SLOTS - 1);
}

static const lockdep_doc_entry_t *doc_lookup(const char *spelling)
{
    char ident[LOCKDEP_NAME_MAX];
    size_t n = 0;

    for (const char *p = spelling; *p; p++) {
        if (*p == '&' || *p == '(' || *p == ')' || *p == ' ')
            continue;
        if (!(*p == '_' || (*p >= 'a' && *p <= 'z') ||
              (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')))
            return NULL;
        if (n + 1 >= sizeof(ident))
            return NULL;
        ident[n++] = *p;
    }
    ident[n] = '\0';
    for (size_t i = 0; i < sizeof(lockdep_doc) / sizeof(lockdep_doc[0]); i++)
        if (!strcmp(lockdep_doc[i].name, ident))
            return &lockdep_doc[i];
    return NULL;
}

static addr_slot_t *addr_find(const void *lock, bool insert)
{
    size_t i = addr_hash(lock);
    addr_slot_t *tomb = NULL;

    for (size_t probe = 0; probe < LOCKDEP_ADDR_SLOTS; probe++) {
        addr_slot_t *s = &addr_map[(i + probe) & (LOCKDEP_ADDR_SLOTS - 1)];
        if (s->key == lock)
            return s;
        if (s->key == ADDR_TOMBSTONE) {
            if (!tomb)
                tomb = s;
            continue;
        }
        if (!s->key)
            return insert ? (tomb ? tomb : s) : NULL;
    }
    return insert ? tomb : NULL;
}

static void class_describe(lock_class_t *c,
                           const lockdep_doc_entry_t *doc,
                           const char *spelling)
{
    c->kind = doc ? doc->kind : KIND_INSTANCE;
    c->rank = doc ? doc->rank : -1;
    snprintf(c->name, sizeof(c->name), "%s", doc ? doc->name : spelling);
}

/* The class for @lock, created on first sight. Called with graph_lock held. An
 * address first seen through a pointer ("lock", "&m->mu") and later through its
 * document name is upgraded in place, keeping the edges it already has.
 */
static int class_of(const void *lock, const char *spelling)
{
    const lockdep_doc_entry_t *doc = doc_lookup(spelling);
    addr_slot_t *s = addr_find(lock, false);

    if (s) {
        lock_class_t *c = &classes[s->cls];
        if (doc && c->kind == KIND_INSTANCE)
            class_describe(c, doc, spelling);
        return s->cls;
    }

    int id;
    if (free_count > 0)
        id = free_ids[--free_count];
    else if (next_id < LOCKDEP_MAX_CLASSES)
        id = next_id++;
    else
        id = -1;
    s = id >= 0 ? addr_find(lock, true) : NULL;
    if (!s) {
        if (!exhausted_reported) {
            exhausted_reported = true;
            fprintf(stderr, "lockdep: class table full, new locks unchecked\n");
        }
        return -1;
    }
    s->key = lock;
    s->cls = id;
    classes[id].used = true;
    class_describe(&classes[id], doc, spelling);
    return id;
}

static bool edge_test(int from, int to)
{
    return adj[from][to / 64] & (1ULL << (to % 64));
}

static edge_site_t *edge_site(int from, int to, bool insert)
{
    uint32_t key = ((uint32_t) (from + 1) << 16) | (uint32_t) (to + 1);
    size_t i = (key * 2654435761U) & (LOCKDEP_EDGE_SLOTS - 1);

    for (size_t probe = 0; probe < LOCKDEP_EDGE_SLOTS; probe++) {
        edge_site_t *e = &edge_sites[(i + probe) & (LOCKDEP_EDGE_SLOTS - 1)];
        if (e->key == key)
            return e;
        if (!e->key) {
            if (!insert)
                return NULL;
            e->key = key;
            return e;
        }
    }
    return NULL;
}

/* Breadth-first search for a path from -> to over recorded edges. On success
 * parent[] traces it back from @to.
 */
static bool path_exists(int from, int to, int *parent)
{
    static uint64_t seen[LOCKDEP_WORDS];
    static int queue[LOCKDEP_MAX_CLASSES];
    int head = 0, tail = 0;

    memset(seen, 0, sizeof(seen));
    queue[tail++] = from;
    seen[from / 64] |= 1ULL << (from % 64);
    parent[from] = -1;
    while (head < tail) {
        int u = queue[head++];
        if (u == to)
            return true;
        for (int w = 0; w < LOCKDEP_WORDS; w++) {
            uint64_t bits = adj[u][w] & ~seen[w];
            while (bits) {
                int v = w * 64 + __builtin_ctzll(bits);
                bits &= bits - 1;
                seen[v / 64] |= 1ULL << (v % 64);
                parent[v] = u;
                queue[tail++] = v;
            }
        }
    }
    return false;
}

static void report_held(void)
{
    fprintf(stderr, "  held by this thread, outermost first:\n");
    for (int i = 0; i < held_depth; i++)
        fprintf(stderr, "    %s at %s:%d\n",
                held[i].cls >= 0 ? classes[held[i].cls].name : "?",
                held[i].file, held[i].line);
}

/* Abort unless ELFUSE_LOCKDEP=warn, in which case each edge reports once. */
static void report_done(void)
{
    const char *mode = getenv("ELFUSE_LOCKDEP");
    if (mode && !strcmp(mode, "warn"))
        return;
    abort();
}

static void check_edge(int h,
                       const held_t *outer,
                       int c,
                       const char *file,
                       int line)
{
    static int parent[LOCKDEP_MAX_CLASSES];
    const lock_class_t *hc = &classes[h], *cc = &classes[c];
    const char *why = NULL;

    if ((hc->kind == KIND_LEAF || hc->kind == KIND_BOTTOM) &&
        cc->kind != KIND_BOTTOM)
        why = "taken while a documented leaf is held";
    else if (hc->kind == KIND_ORDERED && cc->kind == KIND_ORDERED &&
             cc->rank < hc->rank)
        why = "taken against the documented order";

    if (why) {
        fprintf(stderr, "lockdep: %s %s\n  acquiring %s at %s:%d\n", cc->name,
                why, cc->name, file, line);
        report_held();
        fprintf(stderr, "  order document: src/syscall/internal.h\n");
        report_done();
    }

    if (path_exists(c, h, parent)) {
        fprintf(stderr,
                "lockdep: acquiring %s at %s:%d while holding %s closes a "
                "cycle\n  the reverse order was recorded at:\n",
                cc->name, file, line, hc->name);
        for (int v = h; parent[v] >= 0; v = parent[v]) {
            int u = parent[v];
            const edge_site_t *e = edge_site(u, v, false);
            fprintf(stderr, "    %s (held at %s:%d) -> %s (taken at %s:%d)\n",
                    classes[u].name, e ? e->outer_file : "?",
                    e ? e->outer_line : 0, classes[v].name,
                    e ? e->inner_file : "?", e ? e->inner_line : 0);
        }
        report_held();
        report_done();
    }

    adj[h][c / 64] |= 1ULL << (c % 64);
    edge_site_t *e = edge_site(h, c, true);
    if (e) {
        e->outer_file = outer->file;
        e->outer_line = outer->line;
        e->inner_file = file;
        e->inner_line = line;
    }
}

void lockdep_check(const void *lock,
                   const char *spelling,
                   const char *file,
                   int line)
{
    os_unfair_lock_lock(&graph_lock);
    int c = class_of(lock, spelling);
    for (int i = 0; c >= 0 && i < held_depth; i++) {
        int h = held[i].cls;
        if (h < 0)
            continue;
        if (h == c) {
            fprintf(stderr, "lockdep: %s taken again at %s:%d\n",
                    classes[c].name, file, line);
            report_held();
            report_done();
            continue;
        }
        if (!edge_test(h, c))
            check_edge(h, &held[i], c, file, line);
    }
    os_unfair_lock_unlock(&graph_lock);
}

void lockdep_push(const void *lock,
                  const char *spelling,
                  const char *file,
                  int line)
{
    if (held_depth >= LOCKDEP_MAX_HELD)
        return;
    os_unfair_lock_lock(&graph_lock);
    int c = class_of(lock, spelling);
    os_unfair_lock_unlock(&graph_lock);
    held[held_depth++] = (held_t) {lock, c, file, line};
}

/* A lock released by a thread that did not take it (a handoff) is not on this
 * thread's stack; that is not an error here.
 */
void lockdep_pop(const void *lock)
{
    for (int i = held_depth - 1; i >= 0; i--) {
        if (held[i].lock != lock)
            continue;
        memmove(&held[i], &held[i + 1],
                (size_t) (held_depth - i - 1) * sizeof(held[0]));
        held_depth--;
        return;
    }
}

/* A destroyed lock's address may be reused by an unrelated one, so its class
 * and every edge through it go away with it.
 */
void lockdep_forget(const void *lock)
{
    os_unfair_lock_lock(&graph_lock);
    addr_slot_t *s = addr_find(lock, false);
    if (s) {
        int id = s->cls;
        memset(adj[id], 0, sizeof(adj[id]));
        for (int i = 0; i < next_id; i++)
            adj[i][id / 64] &= ~(1ULL << (id % 64));

        /* edge_sites keeps its stale entries: a site is read only for an edge
         * set in adj, and re-adding that edge rewrites its site.
         */
        classes[id].used = false;
        free_ids[free_count++] = id;
        s->key = ADDR_TOMBSTONE;
    }
    os_unfair_lock_unlock(&graph_lock);
}

#else

/* ISO C forbids an empty translation unit. */
typedef int lockdep_disabled_t;

#endif
