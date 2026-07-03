/* Local OCI image store: blobs + tag-to-digest pinning
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wraps the slice-2 content-addressable blob store with a tag-to-digest pin
 * table so that elfuse oci pull / inspect can reproduce a pull by name. The
 * on-disk layout under <root> follows the OCI image-layout spec (v1.0.0) so
 * external tools (skopeo, umoci, crane) can consume the store directly:
 *
 *   oci-layout                               OCI image-layout 1.0.0 marker
 *   index.json                               OCI image-index of all pins
 *   index.json.lock                          flock target for serializing
 * writers blobs/<algo>/<hex>                       finalized blob (immutable)
 *   tmp/blob-<pid>-<seq>-XXXXXX              in-flight blob staging
 *
 * Each pin is one descriptor in index.json's manifests[] array. The pin name
 * (canonical "<registry>/<repository>:<tag>") is stored in the descriptor's
 * org.opencontainers.image.ref.name annotation. The descriptor's mediaType,
 * digest, and size mirror the manifest blob in blobs/<algo>/<hex>. Writers
 * serialize through flock(<root>/index.json.lock, LOCK_EX) and publish via
 * tmp + rename so a concurrent reader always observes a complete document.
 * Readers parse the snapshot lock-free: rename is atomic and cJSON consumes
 * the file in one open + read.
 *
 * <root> is a plain directory; the store is independent of the
 * case-sensitive APFS sysroot volume that oci/volume.c bootstraps
 * separately for unpacked images.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "blob-store.h"
#include "digest-set.h"
#include "ref.h"

typedef struct oci_store oci_store_t;

/* One pin entry produced by oci_store_list_refs. name is the canonical
 * "<registry>/<repository>:<tag>" string captured from the descriptor's
 * org.opencontainers.image.ref.name annotation; digest is the manifest
 * digest in "<algo>:<hex>" form. Both fields are heap-allocated and owned
 * by the enclosing oci_pin_list_t.
 */
typedef struct {
    char *name;
    char *digest;
} oci_pin_entry_t;

typedef struct {
    oci_pin_entry_t *items;
    size_t count;
} oci_pin_list_t;

/* Open or create the store rooted at `root`. Ensures blobs/<algo>/, tmp/,
 * and the OCI image-layout 1.0.0 marker exist. Marker writes are idempotent:
 * a pre-existing oci-layout file is never rewritten so a third party that
 * bumped the imageLayoutVersion is preserved. The index.json file is not
 * materialized until the first oci_store_put_ref so an empty store stays
 * literally empty on disk.
 *
 *
 * The layer cache schema marker at <root>/layers/.schema is also written
 * or validated here: a fresh store gets the current marker stamped; a
 * marker whose schemaVersion is unknown to this build (forward
 * incompatibility, corruption, or an experimental schema) is fatal and
 * returns NULL with errno=EINVAL.
 *
 * Returns NULL on failure with errno preserved.
 */
oci_store_t *oci_store_open(const char *root);

/* Close the store handle. Does not delete on-disk state. Safe on NULL. */
void oci_store_close(oci_store_t *s);

/* Return the store root path. The returned pointer is owned by the store and
 * is valid until oci_store_close.
 */
const char *oci_store_root(const oci_store_t *s);

/* Return the underlying blob store handle. The returned pointer is owned by
 * the store; do not close it directly.
 */
oci_blob_store_t *oci_store_blobs(oci_store_t *s);

/* Return the default store root for the current user. macOS XDG-ish:
 *   $XDG_DATA_HOME/elfuse/store           when XDG_DATA_HOME is set
 *   $HOME/Library/Application Support/elfuse/store   otherwise
 * Returns a heap-allocated string the caller must free, or NULL on env miss
 * (errno=ENOENT) or oom (errno=ENOMEM).
 */
char *oci_store_default_root(void);

/* Upsert a tag-to-digest pin for ref. ref->tag must be set; digest-only refs
 * are self-pinning by their digest field and putting a pin for them is an
 * EINVAL. digest_str is the canonical "<algo>:<hex>" form of the manifest
 * digest captured at pull time; the manifest blob must already be present
 * under <root>/blobs/<algo>/<hex> so the descriptor's size and mediaType
 * can be derived from the on-disk blob (mediaType is read from the JSON
 * body and inferred from structure when absent).
 *
 * Concurrency: the write is serialized by flock(<root>/index.json.lock,
 * LOCK_EX) and published via tmp + rename so a concurrent reader never
 * observes a partial index.json. Re-pinning the same canonical name
 * replaces the existing descriptor in place rather than appending a
 * duplicate entry.
 *
 * Returns 0 on success, -1 with errno preserved and *err_msg (when non-NULL)
 * pointing at a static description on failure.
 */
int oci_store_put_ref(oci_store_t *s,
                      const oci_ref_t *ref,
                      const char *digest_str,
                      const char **err_msg);

/* Read the pinned manifest digest for ref. ref->tag must be set; digest-only
 * refs are self-pinning and trigger EINVAL. On hit returns 0 and writes a
 * heap-allocated "<algo>:<hex>" string into *out_digest (caller frees). On
 * miss returns -1 with errno=ENOENT and *out_digest=NULL. Other IO errors
 * return -1 with errno preserved. *err_msg (when non-NULL) is populated on
 * any non-success path.
 *
 * The read is lock-free: tmp + rename in oci_store_put_ref makes the
 * index.json switch atomic so a single open + read snapshots a complete
 * document.
 */
int oci_store_get_ref(oci_store_t *s,
                      const oci_ref_t *ref,
                      char **out_digest,
                      const char **err_msg);

/* Enumerate every pin currently recorded in index.json. On success returns
 * 0 and populates *out with a heap-allocated array of (name, digest)
 * entries; an empty store yields count == 0 and items == NULL. The caller
 * releases the result via oci_pin_list_free. Missing index.json is treated
 * as an empty store, not as an error. Other IO or schema errors return -1
 * with errno preserved and *err_msg (when non-NULL) populated.
 *
 * The order of returned entries matches the order in index.json; callers
 * that need a stable sort must impose it themselves.
 */
int oci_store_list_refs(oci_store_t *s,
                        oci_pin_list_t *out,
                        const char **err_msg);

/* Release every name / digest string in list and zero the struct. Safe on
 * a zero-initialised list and on NULL.
 */
void oci_pin_list_free(oci_pin_list_t *list);

/* Mark phase of the garbage collector: enumerate every blob digest
 * still reachable from on-disk state and accumulate them in
 * *out. Two sources are walked:
 *
 *   1. Pins in index.json. For each pin's manifest digest, the
 *      manifest blob is read and parsed; the config descriptor and
 *      every layer descriptor are added to the set. If the pinned
 *      blob is an OCI image-index instead of an image manifest, every
 *      sub-manifest descriptor digest is added, and for each
 *      sub-manifest whose blob is on disk the walk recurses into its
 *      config + layers. Sub-manifests not on disk (the multi-arch
 *      case where only one platform was fetched) are still added to
 *      the keep set so a sweep does not delete a sub-manifest blob
 *      that did materialise locally.
 *
 *   2. Unpacked image trees under <volume_root>/images/sha256-<hex>/.
 *      Each tree's .elfuse-origin.json is parsed; its manifest_digest
 *      drives the same manifest/config/layer expansion as a pin.
 *
 * Failure policy is fail-fast on anything that would let prune later
 * delete a reachable blob: a missing manifest blob, an unparseable
 * manifest, a missing or malformed .elfuse-origin.json, or a missing
 * image-config blob all return -1 with *err populated so the operator
 * can repair the store before retrying. A missing
 * <volume_root>/images/ tree is treated as the fresh-store case
 * (count == 0 contribution from that source) and not an error.
 *
 * volume_root may be NULL, in which case the unpacked-tree walk is
 * skipped entirely. The pin walk runs unconditionally.
 *
 * Returns 0 on success; on failure returns -1 with errno preserved
 * and *err (when non-NULL) pointing at a static description. On
 * failure *out is left in a freed-empty state.
 */
int oci_store_collect_roots(oci_store_t *s,
                            oci_digest_set_t *out,
                            const char *volume_root,
                            const char **err);

/* mark walker for the layer + stack caches. Computes the
 * reachable set of layer raw-cache and stack-cache entries from the
 * same two sources oci_store_collect_roots reads: pins in index.json
 * (resolved through one image-index level into a linux/arm64
 * sub-manifest as needed) and unpacked sysroots under
 * <volume_root>/images/. For every image the walker can resolve:
 *
 *   - Every layer's diff_id (from rootfs.diff_ids in the image-config
 *     blob for pinned images, or directly from .elfuse-origin.json's
 *     layer_diffids for unpacked sysroots) is added to *out_diff_ids.
 *     These name the entries under <root>/layers/<algo>/<hex>/.
 *
 *   - Every prefix ChainID through the layer list is added to
 *     *out_chain_ids. ChainID(L0) == DiffID(L0); ChainID(Li) ==
 *     sha256("<prev> <diff_id>"). oci_unpack writes one stack
 *     snapshot per prefix during the apply loop (src/oci/unpack.c
 *     line 1063), so a prune sweep must keep every prefix that maps
 *     to a reachable image, not only the terminating chain. These
 *     name the entries under <root>/layers/stacks/<algo>/<hex>/.
 *
 * Both sets are populated by the same walker pass so they stay
 * consistent across the two sources.
 *
 * Failure policy mirrors oci_store_collect_roots: a missing or
 * unparseable image-config blob for a pinned image-manifest, a
 * malformed origin sidecar, or a chainid_compute failure aborts the
 * mark phase with -1 / errno set so prune cannot proceed to delete
 * reachable cache entries. Soft cases (image-index pins whose
 * linux/arm64 sub-manifest blob is not on disk, image-index pins
 * with no linux/arm64 entry at all, a missing <volume_root>/images/
 * directory) contribute nothing without surfacing as errors so a
 * multi-arch operator stays unblocked.
 *
 * volume_root may be NULL, in which case only the pin source is
 * walked. On entry *out_diff_ids and *out_chain_ids are
 * initialised so the caller may pass uninitialised structs. On
 * failure both sets are freed back to empty.
 */
int oci_store_collect_layer_roots(oci_store_t *s,
                                  oci_digest_set_t *out_diff_ids,
                                  oci_digest_set_t *out_chain_ids,
                                  const char *volume_root,
                                  const char **err);

/* Options + stats for oci_store_prune. Output fields are filled
 * regardless of dry-run vs commit so callers can render a uniform
 * report from the same struct.
 *
 * older_than_sec and keep_bytes shape which dangling entries survive
 * the sweep. Both default to 0 with the documented meaning of "no
 * filter" so every dangling blob is pruned when the caller does not
 * opt in.
 *
 *   older_than_sec > 0 vetoes per-entry: a dangling entry whose mtime
 *   is younger than (now - older_than_sec) is reported in the
 *   skipped_* family and left on disk. This is the grace window for a
 *   half-completed pull whose blob has been committed but whose
 *   put_ref has not landed yet, or for a layer/stack cache entry an
 *   unpack is still publishing.
 *
 *   keep_bytes > 0 enforces a per-family LRU budget over the
 *   candidates that survive the older-than veto: candidates are
 *   sorted by mtime ascending and walked newest-first, the newest
 *   entries whose cumulative size fits under keep_bytes are
 *   reclassified as skipped, the rest stay pruned. A single
 *   candidate that does not fit the budget terminates the keep walk
 *   so older candidates are always evicted first even when an older
 *   entry would fit alone. The budget is applied independently to
 *   each cache family (blobs, layers, stacks) so a fat blob cannot
 *   crowd out a layer-cache eviction.
 *
 * The two filters compose by running older-than first and keep-bytes
 * second per family: a transient just-pulled entry never enters the
 * LRU budget computation so the grace window holds.
 *
 * The extension introduces per-layer and per-stack
 * counters that behave just like the blob counters: kept entries
 * survive the mark phase, pruned entries are unreachable and (when
 * commit is true) recursively removed, skipped entries were
 * unreachable but the filters spared them. layer entries live under
 * <root>/layers/<algo>/<hex>/ and stack entries under
 * <root>/layers/stacks/<algo>/<hex>/; both are directory trees so
 * the *_bytes counters are the recursive st_size sum of every
 * regular file beneath the entry directory.
 */
typedef struct {
    /* Inputs */
    bool commit;             /* false (default) = dry-run; true = unlink */
    const char *volume_root; /* NULL = pin-only walk (see collect_roots) */
    uint64_t older_than_sec; /* 0 = no mtime filter */
    uint64_t keep_bytes;     /* 0 = no size budget (no filter) */

    /* Outputs - blobs */
    size_t kept_blobs;
    size_t pruned_blobs;
    uint64_t pruned_bytes;
    size_t
        skipped_blobs; /* dangling but spared by older_than_sec or keep_bytes */
    uint64_t skipped_bytes; /* sum of st_size for skipped_blobs */

    /* Outputs - per-layer raw cache entries */
    size_t kept_layers;
    size_t pruned_layers;
    uint64_t pruned_layer_bytes;
    size_t skipped_layers;
    uint64_t skipped_layer_bytes;

    /* Outputs - ChainID-keyed stack cache entries */
    size_t kept_stacks;
    size_t pruned_stacks;
    uint64_t pruned_stack_bytes;
    size_t skipped_stacks;
    uint64_t skipped_stack_bytes;
} oci_store_prune_options_t;

/* Garbage-collect dangling entries from three cache families under
 * the store root. The mark phase pairs oci_store_collect_roots (blob
 * keep set) with oci_store_collect_layer_roots (diff_id and ChainID
 * keep sets) so all three sweeps share a single consistent snapshot
 * of pins + unpacked sysroots:
 *
 *   - <root>/blobs/<algo>/<hex>           regular files
 *   - <root>/layers/<algo>/<hex>/         raw layer dirs
 *   - <root>/layers/stacks/<algo>/<hex>/  stack snapshot dirs
 *
 * The sweep phase walks each family in turn, comparing every entry's
 * <algo>:<hex> against its family's keep set; entries not reachable
 * are counted into the family's pruned_* counters and (when
 * opts->commit is true) removed (unlink for blobs, recursive rm for
 * layer / stack directory trees). pruned_layer_bytes and
 * pruned_stack_bytes hold the recursive sum of regular-file st_size
 * beneath each removed directory.
 *
 * The whole operation runs under flock(<root>/index.json.lock,
 * LOCK_EX), which is the same write lock oci_store_put_ref holds.
 * That bounds the race where a concurrent pull writes a new pin
 * after the mark phase already snapshotted index.json. Layer / stack
 * cache writers (oci_unpack / oci_rebuild_cache) do NOT take this
 * lock so they may publish new cache entries concurrent with prune;
 * those entries are reachable from their image's pin or unpacked
 * sysroot, both of which the mark phase already captured, so their
 * diff_id / ChainID is in the keep set even if the directory did
 * not yet exist when sweep enumerated. The remaining window is the
 * mid-pull case (a layer extracted before put_ref lands) which
 * matches the same blob-mid-pull semantic elsewhere in this store:
 * the operator retries.
 *
 * On entry every counter in opts is reset to zero so the caller does
 * not have to memset between invocations. Entries whose name is not
 * a valid lowercase hex digest for the enclosing algorithm subdir,
 * non-directory entries inside layers/, and dotfiles are all skipped
 * without surfacing as errors so any foreign state under the store
 * root stays untouched.
 *
 * When opts->older_than_sec or opts->keep_bytes is set, each family
 * gathers dangling candidates first and then applies the filters
 * (older-than veto, then keep-bytes LRU budget) before any removal.
 * The keep-bytes budget is independent per family: a 100 MiB budget
 * means "keep up to 100 MiB of newest dangling blobs AND up to
 * 100 MiB of newest dangling layer trees AND up to 100 MiB of
 * newest dangling stack trees", so a fat blob cannot crowd a layer
 * eviction off the budget. Candidates spared by either filter
 * contribute to skipped_* rather than pruned_* so the caller can
 * render a three-way kept/pruned/skipped split per family.
 *
 * Returns 0 on success and -1 on failure with errno preserved and
 * *err (when non-NULL) populated. Mark-phase failure is fatal and
 * aborts before any removal so a corrupt or torn manifest / config
 * blob cannot cause prune to delete reachable entries.
 */
int oci_store_prune(oci_store_t *s,
                    oci_store_prune_options_t *opts,
                    const char **err);

/* per-layer unpack snapshot cache.
 *
 * Layer caches live under <root>/layers/<algo>/<hex>/ in the same content-
 * addressed shape as <root>/blobs/<algo>/<hex>. Each cache directory holds a
 * snapshot of the unpack stage_dir state immediately after applying that
 * layer's tar payload. clonefile(2) populates and consumes the snapshots so
 * the cache and the live unpack stage must live on the same APFS volume; an
 * EXDEV during snapshot is propagated as a hard error rather than silently
 * falling back to a copy.
 *
 * Cache semantics are CUMULATIVE: the directory at layers/sha256/<hex>/
 * holds the stage_dir state assembled by the unpacker WHEN this layer was
 * applied, which means it includes every prior layer's contribution along
 * with the current layer. A second unpack of the same image short-circuits
 * the extract loop entirely. Cross-image dedup (two images sharing a base
 * layer prefix but diverging upstream) is not correct under this scheme
 * alone; raw-tar staging + clonefile-stack assembly (below) fixes the
 * cross-image case, with this layout providing the directory structure,
 * the path helpers, and the per-image fast path the stack assembly
 * builds on.
 *
 * oci_store_collect_layer_roots + oci_store_prune extend the keep-set
 * walk to layers/, so the cache does not grow unboundedly; `oci image
 * rebuild-cache` separately back-fills stack snapshots for images
 * unpacked before the cache existed.
 *
 * No refcount sidecar is written. Reachability is recomputed at GC time from
 * each manifest's image-config rootfs.diff_ids list, mirroring how blobs/
 * reachability is recomputed by oci_store_collect_roots.
 *
 * Concurrency: cache_has is a single stat(2) and is inherently racy with
 * concurrent writers, but the worst outcome is a redundant extract.
 * oci_store_layer_commit publishes via rename(2) (atomic) and treats
 * EEXIST / ENOTEMPTY at the destination as a benign loss to a racing
 * winner: the loser's staging directory is removed and 0 is returned so the
 * caller can proceed as though the entry was already on disk. No store-wide
 * lock is required.
 */

/* Probe whether <root>/layers/<algo>/<hex>/ exists. diff_id is in canonical
 * "<algo>:<hex>" form. Returns 1 (present, is a directory), 0 (absent), or
 * -1 with errno preserved on any unexpected IO error. A malformed diff_id
 * returns -1 with errno=EINVAL.
 */
int oci_store_layer_has(oci_store_t *s, const char *diff_id);

/* Compose <root>/layers/<algo>/<hex>/ for diff_id into out. Trailing slash
 * included so a downstream strcat(child) composes cleanly. Pure path
 * computation; does not stat or mkdir. Returns 0 on success, -1 with errno
 * EINVAL on malformed diff_id, ENAMETOOLONG on buffer overflow.
 */
int oci_store_layer_resolve(oci_store_t *s,
                            const char *diff_id,
                            char *out,
                            size_t cap);

/* Compose <root>/layers/.staging/<algo>-<hex>-<rand12> for diff_id into out.
 * The path is unique per call; the directory is NOT created (clonefile(2)
 * creates it as a side effect). Returns 0 on success, -1 with errno EINVAL
 * on malformed diff_id, ENAMETOOLONG on overflow, or other errno values
 * propagated from getentropy(2).
 */
int oci_store_layer_stage_path(oci_store_t *s,
                               const char *diff_id,
                               char *out,
                               size_t cap);

/* Atomically publish a populated staging directory as the layer cache entry
 * for diff_id via rename(stage_path, <root>/layers/<algo>/<hex>/). If the
 * destination already exists (EEXIST / ENOTEMPTY: a concurrent writer landed
 * the same entry first) the staging directory is removed and 0 is returned.
 * Any other failure returns -1 with errno preserved and *err (when non-NULL)
 * populated; the staging directory is left in place so the caller can retry
 * or inspect it.
 */
int oci_store_layer_commit(oci_store_t *s,
                           const char *stage_path,
                           const char *diff_id,
                           const char **err);

/* ChainID-keyed assembled-stack cache.
 *
 * The stack cache lives under <root>/layers/stacks/<algo>/<hex>/ in the same
 * content-addressed shape as the per-layer raw cache. Each entry holds an
 * assembled cumulative stage_dir state through some prefix of an image's
 * layer list, keyed by the OCI ChainID for the terminating layer (see
 * src/oci/digest.h::oci_chainid_compute). Cross-image dedup works because
 * any two images that share the same ordered layer prefix produce the same
 * ChainID for that prefix; the longest-prefix match short-circuits the
 * per-layer assembly during oci_unpack.
 *
 * Staging shares the <root>/layers/.staging/ directory with the per-layer
 * raw cache. Stack stage paths are prefixed with "stack-" so a debug walk
 * of .staging/ can tell the two artifact families apart at a glance. The
 * commit destination is what disambiguates the two on disk.
 *
 * Concurrency mirrors the layer-cache APIs: stack_has is a single stat(2)
 * (racy with concurrent writers; worst case is one redundant assembly),
 * stack_commit publishes via rename(2) and treats EEXIST / ENOTEMPTY as a
 * benign loss to the racing winner with the staging tree torn down. No
 * store-wide lock is required.
 */

/* Probe whether <root>/layers/stacks/<algo>/<hex>/ exists. chain_id is in
 * canonical "<algo>:<hex>" form. Returns 1 (present, is a directory), 0
 * (absent), or -1 with errno preserved on any unexpected IO error. A
 * malformed chain_id returns -1 with errno=EINVAL.
 */
int oci_store_stack_has(oci_store_t *s, const char *chain_id);

/* Compose <root>/layers/stacks/<algo>/<hex>/ for chain_id into out.
 * Trailing slash included so a downstream strcat(child) composes cleanly.
 * Pure path computation; does not stat or mkdir. Returns 0 on success, -1
 * with errno EINVAL on malformed chain_id, ENAMETOOLONG on buffer overflow.
 */
int oci_store_stack_resolve(oci_store_t *s,
                            const char *chain_id,
                            char *out,
                            size_t cap);

/* Compose <root>/layers/.staging/stack-<algo>-<hex>-<rand12> for chain_id
 * into out. The path is unique per call; the directory is NOT created
 * (clonefile(2) creates it as a side effect). Returns 0 on success, -1 with
 * errno EINVAL on malformed chain_id, ENAMETOOLONG on overflow, or other
 * errno values propagated from getentropy(2).
 */
int oci_store_stack_stage_path(oci_store_t *s,
                               const char *chain_id,
                               char *out,
                               size_t cap);

/* Atomically publish a populated staging directory as the stack cache entry
 * for chain_id via rename(stage_path, <root>/layers/stacks/<algo>/<hex>/).
 * If the destination already exists (EEXIST / ENOTEMPTY: a concurrent writer
 * landed the same entry first) the staging directory is removed and 0 is
 * returned. Any other failure returns -1 with errno preserved and *err
 * (when non-NULL) populated; the staging directory is left in place so the
 * caller can retry or inspect it.
 */
int oci_store_stack_commit(oci_store_t *s,
                           const char *stage_path,
                           const char *chain_id,
                           const char **err);
