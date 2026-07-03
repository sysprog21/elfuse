/* OCI image manifest, image index, and image config parsers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "manifest.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cjson/cJSON.h>

/* Maximum representable size that can survive a double round-trip without
 * silent precision loss. JSON numbers parse through double in cJSON, so any
 * size beyond 2^53 - 1 would already be off by ones; sizes well below that
 * cover every realistic OCI layer.
 */
#define SIZE_MAX_SAFE INT64_C(0x1fffffffffffff)

/* Optional string helper. JSON value may be absent (NULL item) or string
 * type. Returns 1 on accepted (out_dup may be empty on success when allow
 * is true), 0 on absent (out_dup left as default), -1 on type error. The
 * caller owns the returned string.
 */
static int dup_optional_string(const cJSON *parent,
                               const char *key,
                               char **out_dup,
                               const char **err_msg,
                               const char *type_err)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(parent, key);
    if (!item)
        return 0;
    if (!cJSON_IsString(item) || !item->valuestring) {
        if (err_msg)
            *err_msg = type_err;
        return -1;
    }
    char *dup = strdup(item->valuestring);
    if (!dup) {
        if (err_msg)
            *err_msg = "out of memory copying string field";
        return -1;
    }
    free(*out_dup);
    *out_dup = dup;
    return 1;
}

static int require_string(const cJSON *parent,
                          const char *key,
                          char **out_dup,
                          const char **err_msg,
                          const char *missing_msg,
                          const char *type_msg)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(parent, key);
    if (!item) {
        if (err_msg)
            *err_msg = missing_msg;
        return -1;
    }
    if (!cJSON_IsString(item) || !item->valuestring) {
        if (err_msg)
            *err_msg = type_msg;
        return -1;
    }
    char *dup = strdup(item->valuestring);
    if (!dup) {
        if (err_msg)
            *err_msg = "out of memory copying required string";
        return -1;
    }
    free(*out_dup);
    *out_dup = dup;
    return 0;
}

/* Convert a JSON string array into a NULL-terminated char** array. Returns
 * 0 on success, -1 on type error or allocation failure. On absent field
 * the function returns 1 and leaves *out_array untouched.
 */
static int dup_string_array(const cJSON *parent,
                            const char *key,
                            char ***out_array,
                            const char **err_msg,
                            const char *type_msg,
                            bool required)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(parent, key);
    if (!item) {
        if (required) {
            if (err_msg)
                *err_msg = type_msg;
            return -1;
        }
        return 1;
    }
    if (!cJSON_IsArray(item)) {
        if (err_msg)
            *err_msg = type_msg;
        return -1;
    }
    int n = cJSON_GetArraySize(item);
    if (n < 0)
        n = 0;
    char **arr = calloc((size_t) n + 1, sizeof(*arr));
    if (!arr) {
        if (err_msg)
            *err_msg = "out of memory allocating string array";
        return -1;
    }
    for (int i = 0; i < n; i++) {
        const cJSON *elem = cJSON_GetArrayItem(item, i);
        if (!cJSON_IsString(elem) || !elem->valuestring) {
            if (err_msg)
                *err_msg = type_msg;
            goto fail;
        }
        arr[i] = strdup(elem->valuestring);
        if (!arr[i]) {
            if (err_msg)
                *err_msg = "out of memory copying string-array element";
            goto fail;
        }
    }
    arr[n] = NULL;
    /* Free any prior value before publishing the new one. */
    if (*out_array) {
        for (char **p = *out_array; *p; p++)
            free(*p);
        free(*out_array);
    }
    *out_array = arr;
    return 0;
fail:
    for (int i = 0; i < n; i++)
        free(arr[i]);
    free(arr);
    return -1;
}

/* Parse a non-negative integer-valued JSON number. cJSON keeps numbers in
 * a double so the practical upper bound is 2^53 - 1; OCI layer sizes are
 * well below that.
 */
static int parse_size_field(const cJSON *parent,
                            const char *key,
                            int64_t *out,
                            const char **err_msg)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(parent, key);
    if (!item) {
        if (err_msg)
            *err_msg = "descriptor missing size field";
        return -1;
    }
    if (!cJSON_IsNumber(item)) {
        if (err_msg)
            *err_msg = "descriptor size field is not a number";
        return -1;
    }
    double v = item->valuedouble;
    if (!(v >= 0.0) || v > (double) SIZE_MAX_SAFE) {
        if (err_msg)
            *err_msg = "descriptor size out of representable range";
        return -1;
    }
    /* Round-trip check: the JSON number must already be an integer. The
     * double-to-int64 cast truncates; reject anything with a fractional part
     * before truncation hides the divergence.
     */
    int64_t as_int = (int64_t) v;
    if ((double) as_int != v) {
        if (err_msg)
            *err_msg = "descriptor size field is not an integer";
        return -1;
    }
    *out = as_int;
    return 0;
}

static int parse_descriptor(const cJSON *obj,
                            oci_descriptor_t *out,
                            const char **err_msg)
{
    memset(out, 0, sizeof(*out));

    /* mediaType: optional per OCI image-spec (some legacy responses omit it
     * on the implicit root), but every descriptor that lives inside another
     * document does carry it. Treat it as required at parse time and let
     * the caller relax it for the top-level document if needed.
     */
    char *raw_mt = NULL;
    if (require_string(obj, "mediaType", &raw_mt, err_msg,
                       "descriptor missing mediaType",
                       "descriptor mediaType must be a string") < 0)
        goto fail;
    out->raw_media_type = raw_mt;
    out->media_type = oci_media_type_parse(raw_mt);

    if (require_string(obj, "digest", &out->digest_str, err_msg,
                       "descriptor missing digest",
                       "descriptor digest must be a string") < 0)
        goto fail;
    if (!oci_digest_parse(out->digest_str, &out->algo, out->hex)) {
        if (err_msg)
            *err_msg = "descriptor digest is malformed or not lowercase";
        goto fail;
    }

    if (parse_size_field(obj, "size", &out->size, err_msg) < 0)
        goto fail;
    return 0;
fail:
    oci_descriptor_free(out);
    return -1;
}

static int parse_platform(const cJSON *obj,
                          oci_platform_t *out,
                          const char **err_msg)
{
    memset(out, 0, sizeof(*out));
    if (!obj || !cJSON_IsObject(obj)) {
        if (err_msg)
            *err_msg = "platform field missing or not an object";
        return -1;
    }
    if (require_string(obj, "architecture", &out->architecture, err_msg,
                       "platform missing architecture",
                       "platform architecture must be a string") < 0)
        goto fail;
    if (require_string(obj, "os", &out->os, err_msg, "platform missing os",
                       "platform os must be a string") < 0)
        goto fail;

    /* variant and os.version default to "" so callers can compare without
     * NULL checks. dup_optional_string sets the field only when present.
     */
    if (dup_optional_string(obj, "variant", &out->variant, err_msg,
                            "platform variant must be a string") < 0)
        goto fail;
    if (!out->variant) {
        out->variant = strdup("");
        if (!out->variant) {
            if (err_msg)
                *err_msg = "out of memory defaulting variant";
            goto fail;
        }
    }
    if (dup_optional_string(obj, "os.version", &out->os_version, err_msg,
                            "platform os.version must be a string") < 0)
        goto fail;
    if (!out->os_version) {
        out->os_version = strdup("");
        if (!out->os_version) {
            if (err_msg)
                *err_msg = "out of memory defaulting os.version";
            goto fail;
        }
    }
    return 0;
fail:
    oci_platform_free(out);
    return -1;
}

static int parse_int_field(const cJSON *parent,
                           const char *key,
                           int *out,
                           bool required,
                           const char **err_msg,
                           const char *missing_msg,
                           const char *type_msg)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(parent, key);
    if (!item) {
        if (required) {
            if (err_msg)
                *err_msg = missing_msg;
            return -1;
        }
        return 1;
    }
    if (!cJSON_IsNumber(item)) {
        if (err_msg)
            *err_msg = type_msg;
        return -1;
    }
    /* Round-trip check: cJSON's valueint truncates the JSON number, so a
     * fractional value like "schemaVersion": 2.7 would otherwise pass an
     * == 2 comparison downstream. Reject anything that is out of int range
     * or carries a fractional part before the truncation hides it.
     */
    double v = item->valuedouble;
    if (v < (double) INT_MIN || v > (double) INT_MAX) {
        if (err_msg)
            *err_msg = type_msg;
        return -1;
    }
    int as_int = (int) v;
    if ((double) as_int != v) {
        if (err_msg)
            *err_msg = type_msg;
        return -1;
    }
    *out = as_int;
    return 0;
}

/* Convert a cJSON parse failure into our diagnostic message space. cJSON's
 * cJSON_GetErrorPtr is process-global; the message we set is static and the
 * caller never frees it.
 */
static void set_parse_err(const char **err_msg, const char *fallback)
{
    if (err_msg)
        *err_msg = fallback;
    errno = EINVAL;
}

int oci_manifest_parse(const char *json,
                       size_t len,
                       oci_manifest_t *out,
                       const char **err_msg)
{
    if (!json || !out) {
        set_parse_err(err_msg, "oci_manifest_parse: NULL input");
        return -1;
    }
    memset(out, 0, sizeof(*out));

    cJSON *root = cJSON_ParseWithLength(json, len);
    if (!root) {
        set_parse_err(err_msg, "manifest JSON is malformed");
        return -1;
    }
    if (!cJSON_IsObject(root)) {
        set_parse_err(err_msg, "manifest JSON root is not an object");
        goto fail;
    }

    if (parse_int_field(root, "schemaVersion", &out->schema_version, true,
                        err_msg, "manifest missing schemaVersion",
                        "manifest schemaVersion must be a number") < 0)
        goto fail;
    if (out->schema_version != 2) {
        set_parse_err(err_msg, "manifest schemaVersion must be 2");
        goto fail;
    }

    /* mediaType on the manifest itself is optional in some Docker responses
     * (the Content-Type header is canonical there); record raw and parsed
     * forms but do not reject on absence.
     */
    if (dup_optional_string(root, "mediaType", &out->raw_media_type, err_msg,
                            "manifest mediaType must be a string") < 0)
        goto fail;
    out->media_type = out->raw_media_type
                          ? oci_media_type_parse(out->raw_media_type)
                          : OCI_MT_UNKNOWN;

    const cJSON *cfg = cJSON_GetObjectItemCaseSensitive(root, "config");
    if (!cfg || !cJSON_IsObject(cfg)) {
        set_parse_err(err_msg, "manifest config descriptor missing");
        goto fail;
    }
    if (parse_descriptor(cfg, &out->config, err_msg) < 0)
        goto fail;
    if (!oci_media_type_is_config(out->config.media_type)) {
        set_parse_err(err_msg, "manifest config has non-config media type");
        goto fail;
    }

    const cJSON *layers = cJSON_GetObjectItemCaseSensitive(root, "layers");
    if (!layers || !cJSON_IsArray(layers)) {
        set_parse_err(err_msg, "manifest layers array missing");
        goto fail;
    }
    int nlayers = cJSON_GetArraySize(layers);
    if (nlayers < 0)
        nlayers = 0;
    if (nlayers > 0) {
        out->layers = calloc((size_t) nlayers, sizeof(*out->layers));
        if (!out->layers) {
            set_parse_err(err_msg, "out of memory allocating layer array");
            errno = ENOMEM;
            goto fail;
        }
    }
    for (int i = 0; i < nlayers; i++) {
        const cJSON *desc = cJSON_GetArrayItem(layers, i);
        if (!cJSON_IsObject(desc)) {
            set_parse_err(err_msg, "manifest layer entry is not an object");
            goto fail;
        }
        if (parse_descriptor(desc, &out->layers[out->nlayers], err_msg) < 0)
            goto fail;
        oci_media_type_t lmt = out->layers[out->nlayers].media_type;
        /* Count the slot now that parse_descriptor has populated (and
         * possibly heap-allocated) it. The validation below can still
         * goto fail; counting first lets oci_manifest_free reclaim it.
         */
        out->nlayers++;
        if (!oci_media_type_is_layer(lmt)) {
            set_parse_err(err_msg, "manifest layer has non-layer media type");
            goto fail;
        }
        if (oci_media_type_is_foreign(lmt)) {
            set_parse_err(err_msg,
                          "manifest references foreign (nondistributable) "
                          "layer; not supported");
            goto fail;
        }
        if (!oci_media_type_is_layer_supported(lmt)) {
            set_parse_err(err_msg,
                          "manifest layer media type is not supported "
                          "(only tar / tar+gzip / tar+zstd)");
            goto fail;
        }
    }

    cJSON_Delete(root);
    return 0;
fail:
    cJSON_Delete(root);
    oci_manifest_free(out);
    return -1;
}

int oci_index_parse(const char *json,
                    size_t len,
                    oci_index_t *out,
                    const char **err_msg)
{
    if (!json || !out) {
        set_parse_err(err_msg, "oci_index_parse: NULL input");
        return -1;
    }
    memset(out, 0, sizeof(*out));

    cJSON *root = cJSON_ParseWithLength(json, len);
    if (!root) {
        set_parse_err(err_msg, "index JSON is malformed");
        return -1;
    }
    if (!cJSON_IsObject(root)) {
        set_parse_err(err_msg, "index JSON root is not an object");
        goto fail;
    }

    if (parse_int_field(root, "schemaVersion", &out->schema_version, true,
                        err_msg, "index missing schemaVersion",
                        "index schemaVersion must be a number") < 0)
        goto fail;
    if (out->schema_version != 2) {
        set_parse_err(err_msg, "index schemaVersion must be 2");
        goto fail;
    }

    if (dup_optional_string(root, "mediaType", &out->raw_media_type, err_msg,
                            "index mediaType must be a string") < 0)
        goto fail;
    out->media_type = out->raw_media_type
                          ? oci_media_type_parse(out->raw_media_type)
                          : OCI_MT_UNKNOWN;

    const cJSON *manifests =
        cJSON_GetObjectItemCaseSensitive(root, "manifests");
    if (!manifests || !cJSON_IsArray(manifests)) {
        set_parse_err(err_msg, "index manifests array missing");
        goto fail;
    }
    int n = cJSON_GetArraySize(manifests);
    if (n < 0)
        n = 0;
    if (n > 0) {
        out->entries = calloc((size_t) n, sizeof(*out->entries));
        if (!out->entries) {
            set_parse_err(err_msg, "out of memory allocating index entries");
            errno = ENOMEM;
            goto fail;
        }
    }
    for (int i = 0; i < n; i++) {
        const cJSON *entry = cJSON_GetArrayItem(manifests, i);
        if (!cJSON_IsObject(entry)) {
            set_parse_err(err_msg, "index manifest entry is not an object");
            goto fail;
        }
        oci_index_entry_t *slot = &out->entries[out->nentries];
        if (parse_descriptor(entry, &slot->desc, err_msg) < 0)
            goto fail;
        /* Count the entry now that slot->desc holds allocated strings; the
         * platform parse below can still goto fail, where oci_index_free
         * must see this slot to reclaim both desc and platform.
         */
        out->nentries++;
        const cJSON *plat = cJSON_GetObjectItemCaseSensitive(entry, "platform");
        if (parse_platform(plat, &slot->platform, err_msg) < 0)
            goto fail;
    }

    cJSON_Delete(root);
    return 0;
fail:
    cJSON_Delete(root);
    oci_index_free(out);
    return -1;
}

int oci_image_config_parse(const char *json,
                           size_t len,
                           oci_image_config_t *out,
                           const char **err_msg)
{
    if (!json || !out) {
        set_parse_err(err_msg, "oci_image_config_parse: NULL input");
        return -1;
    }
    memset(out, 0, sizeof(*out));

    cJSON *root = cJSON_ParseWithLength(json, len);
    if (!root) {
        set_parse_err(err_msg, "image config JSON is malformed");
        return -1;
    }
    if (!cJSON_IsObject(root)) {
        set_parse_err(err_msg, "image config JSON root is not an object");
        goto fail;
    }

    if (require_string(root, "architecture", &out->architecture, err_msg,
                       "image config missing architecture",
                       "image config architecture must be a string") < 0)
        goto fail;
    if (require_string(root, "os", &out->os, err_msg, "image config missing os",
                       "image config os must be a string") < 0)
        goto fail;
    if (dup_optional_string(root, "variant", &out->variant, err_msg,
                            "image config variant must be a string") < 0)
        goto fail;

    const cJSON *cfg = cJSON_GetObjectItemCaseSensitive(root, "config");
    if (cfg) {
        if (!cJSON_IsObject(cfg)) {
            set_parse_err(err_msg, "image config.config must be an object");
            goto fail;
        }
        if (dup_optional_string(cfg, "User", &out->config.user, err_msg,
                                "image config User must be a string") < 0)
            goto fail;
        if (dup_optional_string(cfg, "WorkingDir", &out->config.working_dir,
                                err_msg,
                                "image config WorkingDir must be a string") < 0)
            goto fail;
        if (dup_string_array(cfg, "Env", &out->config.env, err_msg,
                             "image config Env must be a string array",
                             false) < 0)
            goto fail;
        if (dup_string_array(
                cfg, "Entrypoint", &out->config.entrypoint, err_msg,
                "image config Entrypoint must be a string array", false) < 0)
            goto fail;
        if (dup_string_array(cfg, "Cmd", &out->config.cmd, err_msg,
                             "image config Cmd must be a string array",
                             false) < 0)
            goto fail;
    }

    const cJSON *rootfs = cJSON_GetObjectItemCaseSensitive(root, "rootfs");
    if (!rootfs || !cJSON_IsObject(rootfs)) {
        set_parse_err(err_msg, "image config rootfs object missing");
        goto fail;
    }
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(rootfs, "type");
    if (!type || !cJSON_IsString(type) || !type->valuestring ||
        strcmp(type->valuestring, "layers") != 0) {
        set_parse_err(err_msg, "image config rootfs.type must be \"layers\"");
        goto fail;
    }
    if (dup_string_array(rootfs, "diff_ids", &out->rootfs_diff_ids, err_msg,
                         "image config rootfs.diff_ids must be a string "
                         "array",
                         true) < 0)
        goto fail;
    /* Validate every diff_id is a recognized digest. */
    for (char **p = out->rootfs_diff_ids; p && *p; p++) {
        oci_digest_algo_t algo;
        char hex[OCI_DIGEST_HEX_MAX + 1];
        if (!oci_digest_parse(*p, &algo, hex)) {
            set_parse_err(err_msg,
                          "image config rootfs.diff_ids entry is malformed "
                          "or not lowercase");
            goto fail;
        }
    }

    cJSON_Delete(root);
    return 0;
fail:
    cJSON_Delete(root);
    oci_image_config_free(out);
    return -1;
}

void oci_descriptor_free(oci_descriptor_t *d)
{
    if (!d)
        return;
    free(d->digest_str);
    free(d->raw_media_type);
    memset(d, 0, sizeof(*d));
}

void oci_platform_free(oci_platform_t *p)
{
    if (!p)
        return;
    free(p->architecture);
    free(p->os);
    free(p->variant);
    free(p->os_version);
    memset(p, 0, sizeof(*p));
}

static void runtime_free(oci_image_runtime_t *r)
{
    if (!r)
        return;
    free(r->user);
    free(r->working_dir);
    if (r->env) {
        for (char **p = r->env; *p; p++)
            free(*p);
        free(r->env);
    }
    if (r->entrypoint) {
        for (char **p = r->entrypoint; *p; p++)
            free(*p);
        free(r->entrypoint);
    }
    if (r->cmd) {
        for (char **p = r->cmd; *p; p++)
            free(*p);
        free(r->cmd);
    }
    memset(r, 0, sizeof(*r));
}

void oci_manifest_free(oci_manifest_t *m)
{
    if (!m)
        return;
    free(m->raw_media_type);
    oci_descriptor_free(&m->config);
    for (size_t i = 0; i < m->nlayers; i++)
        oci_descriptor_free(&m->layers[i]);
    free(m->layers);
    memset(m, 0, sizeof(*m));
}

void oci_index_free(oci_index_t *idx)
{
    if (!idx)
        return;
    free(idx->raw_media_type);
    for (size_t i = 0; i < idx->nentries; i++) {
        oci_descriptor_free(&idx->entries[i].desc);
        oci_platform_free(&idx->entries[i].platform);
    }
    free(idx->entries);
    memset(idx, 0, sizeof(*idx));
}

void oci_image_config_free(oci_image_config_t *c)
{
    if (!c)
        return;
    free(c->architecture);
    free(c->os);
    free(c->variant);
    runtime_free(&c->config);
    if (c->rootfs_diff_ids) {
        for (char **p = c->rootfs_diff_ids; *p; p++)
            free(*p);
        free(c->rootfs_diff_ids);
    }
    memset(c, 0, sizeof(*c));
}

const oci_index_entry_t *oci_index_pick_linux_arm64(const oci_index_t *idx)
{
    if (!idx || !idx->entries)
        return NULL;

    const oci_index_entry_t *fallback_empty = NULL;
    const oci_index_entry_t *fallback_any = NULL;

    for (size_t i = 0; i < idx->nentries; i++) {
        const oci_index_entry_t *e = &idx->entries[i];
        if (strcmp(e->platform.os, "linux") != 0)
            continue;
        if (strcmp(e->platform.architecture, "arm64") != 0)
            continue;
        /* Skip foreign or unrecognized manifest media types: the registry
         * fetch path cannot consume them anyway, so they are not viable
         * even when the platform matches.
         */
        if (!oci_media_type_is_manifest(e->desc.media_type))
            continue;
        if (strcmp(e->platform.variant, "v8") == 0)
            return e;
        if (e->platform.variant[0] == '\0') {
            if (!fallback_empty)
                fallback_empty = e;
        } else if (!fallback_any) {
            fallback_any = e;
        }
    }
    return fallback_empty ? fallback_empty : fallback_any;
}
