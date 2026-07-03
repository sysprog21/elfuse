/* OCI unpacked-tree provenance sidecar implementation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include "oci/origin-meta.h"
#include "oci/util.h"

#define OCI_ORIGIN_FILE ".elfuse-origin.json"

/* Conservative ceiling. A realistic sidecar is a few hundred bytes
 * (three short JSON strings plus an array of ~64 byte diff_id entries).
 * Anything past 1 MiB indicates a corrupt or hostile file and is
 * rejected so the reader does not try to malloc gigabytes from a
 * stat-spoofed input.
 */
#define OCI_ORIGIN_MAX_BYTES (1u << 20)

static char *build_path(const char *root_dir, const char *name, int tmp)
{
    size_t want = strlen(root_dir) + 1 + strlen(name) + (tmp ? 4 : 0) + 1;
    char *p = malloc(want);
    if (!p)
        return NULL;
    snprintf(p, want, "%s/%s%s", root_dir, name, tmp ? ".tmp" : "");
    return p;
}

int oci_origin_write(const char *root_dir,
                     const char *manifest_digest,
                     const char *config_digest,
                     char *const *diff_ids,
                     const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!root_dir || !manifest_digest || !config_digest)
        return set_err(err, "origin write: NULL argument", EINVAL);
    if (!root_dir[0] || !manifest_digest[0] || !config_digest[0])
        return set_err(err, "origin write: empty argument", EINVAL);

    cJSON *root = cJSON_CreateObject();
    if (!root)
        return set_err(err, "origin write: cJSON_CreateObject failed", ENOMEM);
    if (!cJSON_AddStringToObject(root, "manifest_digest", manifest_digest)) {
        cJSON_Delete(root);
        return set_err(err, "origin write: manifest_digest add failed", ENOMEM);
    }
    if (!cJSON_AddStringToObject(root, "config_digest", config_digest)) {
        cJSON_Delete(root);
        return set_err(err, "origin write: config_digest add failed", ENOMEM);
    }
    cJSON *arr = cJSON_AddArrayToObject(root, "layer_diffids");
    if (!arr) {
        cJSON_Delete(root);
        return set_err(err, "origin write: layer_diffids add failed", ENOMEM);
    }
    if (diff_ids) {
        for (char *const *p = diff_ids; *p; p++) {
            cJSON *s = cJSON_CreateString(*p);
            if (!s) {
                cJSON_Delete(root);
                return set_err(err, "origin write: diff_id string failed",
                               ENOMEM);
            }
            cJSON_AddItemToArray(arr, s);
        }
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json)
        return set_err(err, "origin write: cJSON_Print failed", ENOMEM);
    size_t jlen = strlen(json);

    char *tmp_path = build_path(root_dir, OCI_ORIGIN_FILE, 1);
    char *final_path = build_path(root_dir, OCI_ORIGIN_FILE, 0);
    if (!tmp_path || !final_path) {
        free(tmp_path);
        free(final_path);
        free(json);
        return set_err(err, "origin write: path allocation failed", ENOMEM);
    }

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        int saved = errno;
        free(tmp_path);
        free(final_path);
        free(json);
        return set_err(err, "origin write: open tmp failed", saved);
    }
    if (write(fd, json, jlen) != (ssize_t) jlen) {
        int saved = errno ? errno : EIO;
        close(fd);
        unlink(tmp_path);
        free(tmp_path);
        free(final_path);
        free(json);
        return set_err(err, "origin write: write failed", saved);
    }
    if (fsync(fd) < 0) {
        int saved = errno;
        close(fd);
        unlink(tmp_path);
        free(tmp_path);
        free(final_path);
        free(json);
        return set_err(err, "origin write: fsync failed", saved);
    }
    close(fd);
    if (rename(tmp_path, final_path) < 0) {
        int saved = errno;
        unlink(tmp_path);
        free(tmp_path);
        free(final_path);
        free(json);
        return set_err(err, "origin write: rename failed", saved);
    }

    free(tmp_path);
    free(final_path);
    free(json);
    return 0;
}

void oci_origin_free(oci_origin_t *o)
{
    if (!o)
        return;
    free(o->manifest_digest);
    free(o->config_digest);
    if (o->layer_diffids) {
        for (char **p = o->layer_diffids; *p; p++)
            free(*p);
        free((void *) o->layer_diffids);
    }
    o->manifest_digest = NULL;
    o->config_digest = NULL;
    o->layer_diffids = NULL;
}

/* Slurp <root_dir>/<OCI_ORIGIN_FILE> into a heap buffer. Returns the
 * buffer (NUL-terminated for safety against cJSON) on success and
 * writes the byte length into *out_len; returns NULL on failure with
 * errno and *err populated.
 */
static char *slurp_origin(const char *root_dir,
                          size_t *out_len,
                          const char **err)
{
    char *path = build_path(root_dir, OCI_ORIGIN_FILE, 0);
    if (!path) {
        set_err(err, "origin read: path alloc failed", ENOMEM);
        return NULL;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        int saved = errno;
        set_err(err, "origin read: open failed", saved);
        free(path);
        return NULL;
    }
    free(path);
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved = errno;
        close(fd);
        set_err(err, "origin read: fstat failed", saved);
        return NULL;
    }
    if (st.st_size <= 0 || (unsigned long) st.st_size > OCI_ORIGIN_MAX_BYTES) {
        close(fd);
        set_err(err, "origin read: file size out of bounds", EINVAL);
        return NULL;
    }
    size_t len = (size_t) st.st_size;
    char *buf = malloc(len + 1);
    if (!buf) {
        close(fd);
        set_err(err, "origin read: alloc failed", ENOMEM);
        return NULL;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t got = read(fd, buf + off, len - off);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            int saved = errno;
            free(buf);
            close(fd);
            set_err(err, "origin read: read failed", saved);
            return NULL;
        }
        if (got == 0)
            break;
        off += (size_t) got;
    }
    close(fd);
    if (off != len) {
        free(buf);
        set_err(err, "origin read: short read", EIO);
        return NULL;
    }
    buf[len] = '\0';
    *out_len = len;
    return buf;
}

int oci_origin_read(const char *root_dir, oci_origin_t *out, const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!root_dir || !out)
        return set_err(err, "origin read: NULL argument", EINVAL);
    if (!root_dir[0])
        return set_err(err, "origin read: empty root_dir", EINVAL);
    out->manifest_digest = NULL;
    out->config_digest = NULL;
    out->layer_diffids = NULL;

    size_t json_len = 0;
    char *json = slurp_origin(root_dir, &json_len, err);
    if (!json)
        return -1;

    cJSON *root = cJSON_ParseWithLength(json, json_len);
    free(json);
    if (!root)
        return set_err(err, "origin read: JSON parse failed", EINVAL);

    const cJSON *m_field =
        cJSON_GetObjectItemCaseSensitive(root, "manifest_digest");
    const cJSON *c_field =
        cJSON_GetObjectItemCaseSensitive(root, "config_digest");
    const cJSON *l_field =
        cJSON_GetObjectItemCaseSensitive(root, "layer_diffids");
    if (!cJSON_IsString(m_field) || !m_field->valuestring ||
        !m_field->valuestring[0]) {
        cJSON_Delete(root);
        return set_err(err, "origin read: missing manifest_digest field",
                       EINVAL);
    }
    if (!cJSON_IsString(c_field) || !c_field->valuestring ||
        !c_field->valuestring[0]) {
        cJSON_Delete(root);
        return set_err(err, "origin read: missing config_digest field", EINVAL);
    }
    if (!cJSON_IsArray(l_field)) {
        cJSON_Delete(root);
        return set_err(err, "origin read: missing layer_diffids array", EINVAL);
    }

    int n_diffs = cJSON_GetArraySize(l_field);
    if (n_diffs < 0) {
        cJSON_Delete(root);
        return set_err(err, "origin read: layer_diffids size invalid", EINVAL);
    }

    /* +1 slot for the NULL terminator so callers can iterate with the
     * idiomatic `for (p = arr; *p; p++)` pattern.
     */
    void *diffs_raw = calloc((size_t) n_diffs + 1, sizeof(char *));
    if (!diffs_raw) {
        cJSON_Delete(root);
        return set_err(err, "origin read: diff array alloc failed", ENOMEM);
    }
    char **diffs = (char **) diffs_raw;
    for (int i = 0; i < n_diffs; i++) {
        const cJSON *entry = cJSON_GetArrayItem(l_field, i);
        if (!cJSON_IsString(entry) || !entry->valuestring ||
            !entry->valuestring[0]) {
            for (int k = 0; k < i; k++)
                free(diffs[k]);
            free((void *) diffs);
            cJSON_Delete(root);
            return set_err(err,
                           "origin read: layer_diffids entry is not a "
                           "non-empty string",
                           EINVAL);
        }
        diffs[i] = strdup(entry->valuestring);
        if (!diffs[i]) {
            for (int k = 0; k < i; k++)
                free(diffs[k]);
            free((void *) diffs);
            cJSON_Delete(root);
            return set_err(err, "origin read: diff strdup failed", ENOMEM);
        }
    }

    char *m_copy = strdup(m_field->valuestring);
    char *c_copy = strdup(c_field->valuestring);
    cJSON_Delete(root);
    if (!m_copy || !c_copy) {
        free(m_copy);
        free(c_copy);
        for (int k = 0; k < n_diffs; k++)
            free(diffs[k]);
        free((void *) diffs);
        return set_err(err, "origin read: digest strdup failed", ENOMEM);
    }

    out->manifest_digest = m_copy;
    out->config_digest = c_copy;
    out->layer_diffids = diffs;
    return 0;
}
