/* OCI sidecar metadata implementation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include "oci/layer-meta.h"

#define OCI_META_FILE ".elfuse-meta.json"
/* Version 2: layer-apply rewrites absolute symlink targets to relative
 * (abs_target_to_relative), so trees cached under version 1 carry the old
 * host-escaping spelling. The version gates the cached TREE layout, not
 * just this sidecar's JSON schema; readers treat a mismatch as a cache
 * miss and rebuild.
 */
#define OCI_META_VERSION 2

typedef struct {
    char *path;
    uint64_t uid;
    uint64_t gid;
    uint32_t mode;
} oci_meta_entry_t;

struct oci_meta_table {
    oci_meta_entry_t *entries;
    size_t len;
    size_t cap;
};

oci_meta_table_t *oci_meta_table_new(void)
{
    return calloc(1, sizeof(oci_meta_table_t));
}

static void entry_clear(oci_meta_entry_t *e)
{
    free(e->path);
    e->path = NULL;
}

void oci_meta_table_free(oci_meta_table_t *t)
{
    if (!t)
        return;
    for (size_t i = 0; i < t->len; i++)
        entry_clear(&t->entries[i]);
    free(t->entries);
    free(t);
}

static int grow_if_needed(oci_meta_table_t *t)
{
    if (t->len < t->cap)
        return 0;
    size_t nc = t->cap == 0 ? 16 : t->cap * 2;
    oci_meta_entry_t *grown = realloc(t->entries, nc * sizeof(*grown));
    if (!grown)
        return -1;
    t->entries = grown;
    t->cap = nc;
    return 0;
}

static ssize_t find_index(const oci_meta_table_t *t, const char *path)
{
    /* Linear scan. OCI layers typically hold a few hundred to a few
     * thousand entries; the wall cost is dwarfed by the IO each entry
     * already triggers. If profiling later shows this is hot, swap in
     * an open-addressing hash keyed by FNV-1a of the path string.
     */
    for (size_t i = 0; i < t->len; i++)
        if (strcmp(t->entries[i].path, path) == 0)
            return (ssize_t) i;
    return -1;
}

int oci_meta_record(oci_meta_table_t *t,
                    const char *guest_path,
                    uint64_t uid,
                    uint64_t gid,
                    uint32_t mode)
{
    if (!t || !guest_path) {
        errno = EINVAL;
        return -1;
    }
    ssize_t idx = find_index(t, guest_path);
    if (idx >= 0) {
        t->entries[idx].uid = uid;
        t->entries[idx].gid = gid;
        t->entries[idx].mode = mode;
        return 0;
    }
    if (grow_if_needed(t) < 0) {
        errno = ENOMEM;
        return -1;
    }
    char *dup = strdup(guest_path);
    if (!dup) {
        errno = ENOMEM;
        return -1;
    }
    t->entries[t->len].path = dup;
    t->entries[t->len].uid = uid;
    t->entries[t->len].gid = gid;
    t->entries[t->len].mode = mode;
    t->len++;
    return 0;
}

void oci_meta_remove(oci_meta_table_t *t, const char *guest_path)
{
    if (!t || !guest_path)
        return;
    ssize_t idx = find_index(t, guest_path);
    if (idx < 0)
        return;
    entry_clear(&t->entries[idx]);
    /* Move last entry into the freed slot to keep the array compact. */
    if ((size_t) idx != t->len - 1)
        t->entries[idx] = t->entries[t->len - 1];
    t->len--;
}

int oci_meta_lookup(const oci_meta_table_t *t,
                    const char *guest_path,
                    uint64_t *out_uid,
                    uint64_t *out_gid,
                    uint32_t *out_mode)
{
    if (!t || !guest_path) {
        errno = EINVAL;
        return -1;
    }
    ssize_t idx = find_index(t, guest_path);
    if (idx < 0) {
        errno = ENOENT;
        return -1;
    }
    if (out_uid)
        *out_uid = t->entries[idx].uid;
    if (out_gid)
        *out_gid = t->entries[idx].gid;
    if (out_mode)
        *out_mode = t->entries[idx].mode;
    return 0;
}

size_t oci_meta_count(const oci_meta_table_t *t)
{
    return t ? t->len : 0;
}

static char *build_path(const char *root_dir, const char *name, bool tmp)
{
    size_t want = strlen(root_dir) + 1 + strlen(name) + (tmp ? 4 : 0) + 1;
    char *p = malloc(want);
    if (!p)
        return NULL;
    snprintf(p, want, "%s/%s%s", root_dir, name, tmp ? ".tmp" : "");
    return p;
}

static bool valid_basename(const char *filename)
{
    if (!filename || !*filename)
        return false;
    for (const char *p = filename; *p; p++)
        if (*p == '/')
            return false;
    return true;
}

int oci_meta_write_named(const oci_meta_table_t *t,
                         const char *root_dir,
                         const char *filename,
                         const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!root_dir) {
        *err = "meta write: NULL root";
        errno = EINVAL;
        return -1;
    }
    if (!valid_basename(filename)) {
        *err = "meta write: filename must be a non-empty basename";
        errno = EINVAL;
        return -1;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        *err = "meta write: cJSON_CreateObject failed";
        errno = ENOMEM;
        return -1;
    }
    if (!cJSON_AddNumberToObject(root, "version", OCI_META_VERSION)) {
        cJSON_Delete(root);
        *err = "meta write: version add failed";
        errno = ENOMEM;
        return -1;
    }
    cJSON *arr = cJSON_AddArrayToObject(root, "entries");
    if (!arr) {
        cJSON_Delete(root);
        *err = "meta write: entries add failed";
        errno = ENOMEM;
        return -1;
    }
    for (size_t i = 0; t && i < t->len; i++) {
        cJSON *e = cJSON_CreateObject();
        if (!e) {
            cJSON_Delete(root);
            *err = "meta write: entry object failed";
            errno = ENOMEM;
            return -1;
        }
        cJSON_AddItemToArray(arr, e);
        if (!cJSON_AddStringToObject(e, "p", t->entries[i].path) ||
            !cJSON_AddNumberToObject(e, "u", (double) t->entries[i].uid) ||
            !cJSON_AddNumberToObject(e, "g", (double) t->entries[i].gid) ||
            !cJSON_AddNumberToObject(e, "m", (double) t->entries[i].mode)) {
            cJSON_Delete(root);
            *err = "meta write: entry field failed";
            errno = ENOMEM;
            return -1;
        }
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) {
        *err = "meta write: cJSON_Print failed";
        errno = ENOMEM;
        return -1;
    }
    size_t jlen = strlen(json);

    char *tmp_path = build_path(root_dir, filename, true);
    char *final_path = build_path(root_dir, filename, false);
    if (!tmp_path || !final_path) {
        free(tmp_path);
        free(final_path);
        free(json);
        *err = "meta write: path allocation failed";
        errno = ENOMEM;
        return -1;
    }

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        *err = "meta write: open tmp failed";
        goto fail_paths;
    }
    if (write(fd, json, jlen) != (ssize_t) jlen) {
        *err = "meta write: write failed";
        close(fd);
        unlink(tmp_path);
        goto fail_paths;
    }
    if (fsync(fd) < 0) {
        *err = "meta write: fsync failed";
        close(fd);
        unlink(tmp_path);
        goto fail_paths;
    }
    close(fd);
    if (rename(tmp_path, final_path) < 0) {
        *err = "meta write: rename failed";
        unlink(tmp_path);
        goto fail_paths;
    }

    free(tmp_path);
    free(final_path);
    free(json);
    return 0;

fail_paths:
    free(tmp_path);
    free(final_path);
    free(json);
    return -1;
}

int oci_meta_read_named(const char *root_dir,
                        const char *filename,
                        oci_meta_table_t **out,
                        const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!root_dir || !out) {
        *err = "meta read: NULL argument";
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    if (!valid_basename(filename)) {
        *err = "meta read: filename must be a non-empty basename";
        errno = EINVAL;
        return -1;
    }

    char *path = build_path(root_dir, filename, false);
    if (!path) {
        *err = "meta read: path allocation failed";
        errno = ENOMEM;
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        *err = "meta read: open failed";
        free(path);
        return -1; /* errno already ENOENT or similar */
    }
    free(path);

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        *err = "meta read: fstat failed";
        return -1;
    }
    /* Cap at 64 MiB so a corrupt sidecar cannot drag the host into
     * swap; real-world tables are under a few hundred KiB.
     */
    if (st.st_size <= 0 || st.st_size > (off_t) (64 * 1024 * 1024)) {
        close(fd);
        *err = "meta read: file size out of bounds";
        errno = EINVAL;
        return -1;
    }
    char *buf = malloc((size_t) st.st_size + 1);
    if (!buf) {
        close(fd);
        *err = "meta read: buffer allocation failed";
        errno = ENOMEM;
        return -1;
    }
    ssize_t got = read(fd, buf, (size_t) st.st_size);
    close(fd);
    if (got != st.st_size) {
        free(buf);
        *err = "meta read: short read";
        errno = EIO;
        return -1;
    }
    buf[got] = '\0';

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        *err = "meta read: malformed JSON";
        errno = EINVAL;
        return -1;
    }
    cJSON *version = cJSON_GetObjectItemCaseSensitive(root, "version");
    if (!cJSON_IsNumber(version) || version->valueint != OCI_META_VERSION) {
        cJSON_Delete(root);
        *err = "meta read: unsupported version";
        errno = EINVAL;
        return -1;
    }
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "entries");
    if (!cJSON_IsArray(arr)) {
        cJSON_Delete(root);
        *err = "meta read: missing entries array";
        errno = EINVAL;
        return -1;
    }

    oci_meta_table_t *table = oci_meta_table_new();
    if (!table) {
        cJSON_Delete(root);
        *err = "meta read: table allocation failed";
        errno = ENOMEM;
        return -1;
    }

    cJSON *e;
    cJSON_ArrayForEach(e, arr)
    {
        cJSON *p = cJSON_GetObjectItemCaseSensitive(e, "p");
        cJSON *u = cJSON_GetObjectItemCaseSensitive(e, "u");
        cJSON *g = cJSON_GetObjectItemCaseSensitive(e, "g");
        cJSON *m = cJSON_GetObjectItemCaseSensitive(e, "m");
        if (!cJSON_IsString(p) || !cJSON_IsNumber(u) || !cJSON_IsNumber(g) ||
            !cJSON_IsNumber(m)) {
            oci_meta_table_free(table);
            cJSON_Delete(root);
            *err = "meta read: entry shape invalid";
            errno = EINVAL;
            return -1;
        }
        if (oci_meta_record(table, p->valuestring, (uint64_t) u->valuedouble,
                            (uint64_t) g->valuedouble,
                            (uint32_t) m->valuedouble) < 0) {
            oci_meta_table_free(table);
            cJSON_Delete(root);
            *err = "meta read: record failed";
            return -1;
        }
    }

    cJSON_Delete(root);
    *out = table;
    return 0;
}

int oci_meta_write(const oci_meta_table_t *t,
                   const char *root_dir,
                   const char **err)
{
    return oci_meta_write_named(t, root_dir, OCI_META_FILE, err);
}

int oci_meta_read(const char *root_dir,
                  oci_meta_table_t **out,
                  const char **err)
{
    return oci_meta_read_named(root_dir, OCI_META_FILE, out, err);
}

int oci_meta_merge(oci_meta_table_t *dst, const oci_meta_table_t *src)
{
    if (!dst || !src) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < src->len; i++) {
        const oci_meta_entry_t *e = &src->entries[i];
        if (oci_meta_record(dst, e->path, e->uid, e->gid, e->mode) < 0)
            return -1;
    }
    return 0;
}
