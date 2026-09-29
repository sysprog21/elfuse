# OCI Images

An OCI image packages a filesystem as ordered, content-addressed layers plus a
JSON configuration. A manifest names the configuration and layers, and an
image index can select among manifests for different operating systems and
architectures. An OCI image layout stores those objects in a directory without
requiring a registry or a container daemon. This is separate from the OCI
runtime specification, which describes how a container is started.

`elfuse-oci` is a separate Go command that pulls images into such a local
layout and unpacks their filesystems. It does not run images or add namespaces,
cgroups, or other container isolation. Command syntax is in
[usage.md](usage.md#oci-images).

## Store

The store is an [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md):

```text
<store>/
  .lock
  .elfuse-oci-store
  oci-layout
  index.json
  blobs/<algorithm>/<digest>
  rootfs/sha256/<hex>
```

The marker records the elfuse store format. `oci-layout`, `index.json`, and
`blobs/` follow the OCI image-layout specification. `.lock` is internal store
metadata and serializes layout initialization and pin-table updates. Registry
transfers and content-addressed blob writes happen outside that critical
section, so an unrelated pull does not wait for another image's download.

`index.json` contains one descriptor for each canonical image reference. Its
`org.opencontainers.image.ref.name` annotation holds the reference. That
descriptor names another OCI index whose children are the manifests pulled
for each platform. Pulling `alpine:3` and
`docker.io/library/alpine:3` updates the same entry.

Blobs are written and synced before either index names them. On a fresh store,
the blob directory hierarchy is also synced up to the store root before the
pin table is replaced. `index.json` is replaced atomically. Existing blobs are
streamed through their digest before reuse instead of being loaded into
memory. Stale temporary metadata files left by an interrupted replacement are
removed while `.lock` is held.

The store and blob directories use mode 0700. Metadata and the lock use 0600,
and immutable blobs use 0400, so another local user cannot read a private
image through default permissions.

The store is a cache. A directory that carries no format marker but does hold
`refs.json` has an incompatible format and is rejected; remove it and pull the
image again. `unpack` applies the same format checks as `pull` but never
creates or repairs the store.

A failed pull can leave unreferenced blobs, and pulling a moved tag can leave
the old blobs unreferenced. This version has no pruning command. To reclaim
that space, stop all pulls, remove the entire store directory, and pull the
needed images again. Do not remove individual blobs because an OCI index may
still reference them.

## Pull

`go-containerregistry` parses references, reads Docker or Podman credentials,
selects a platform, and fetches the image. A bare manifest is checked against
the platform in its config before publication.

The supported targets are `linux/arm64` and `linux/amd64`. The aliases
`linux/aarch64`, `linux/arm64/v8`, and `linux/x86_64` resolve to those two
keys. The default is `linux/arm64`. Selection compares the normalized OS,
architecture, and variant exactly; for example, an `amd64/v3` image is not
pinned as baseline `amd64`.

The pull timeout covers the registry request, store publication, and the wait
for another writer. The default value, zero, does not set a deadline.

## Unpack

Without `--rootfs`, `unpack` caches the rootfs under the store by manifest
digest. It extracts into a sibling temporary directory and renames the
completed tree into place, so concurrent unpacks may duplicate work but only a
completed tree is published. The cache takes the store's 0700 mode, a symlink
at a cache path is rejected, and the next unpack that extracts into the cache
removes staging trees older than a day. A cached tree is reused as is; remove
it to unpack again.

`--rootfs DIR` applies the image to `DIR`, following a symlink to it. An
existing directory is updated in place; an absent one is staged and renamed,
and losing that rename is an error. A destination inside the store, or one
containing it, is rejected.

Layers are applied in manifest order by `moby/go-archive`, which handles
whiteouts, hardlinks, path containment, file metadata, and decompression.
Ownership is not applied, and unsupported extended attributes do not fail
extraction. elfuse rewrites each entry before go-archive sees it:

- Device and FIFO entries, and hardlinks to them, become whiteouts, so no
  lower-layer file survives at their paths.
- Absolute symlink targets are rewritten relative to the link's on-disk
  parent, the rewrite `symlinkat` applies inside a sysroot
  ([filenames.md](filenames.md#symlink-targets)); a hardlink to such a
  symlink is rebased at its own location.
- Directory modes are restored after all layers are applied, so a read-only
  directory still receives later entries.
- Setuid, setgid, and sticky bits are cleared.

## Validation

The offline tests create manifests and layers in temporary stores. They cover
reference normalization, exact platform selection, index structure, blob
validation, credential-helper resolution, concurrent pulls, stale temporary
files, private permissions, legacy-store refusal, lock cancellation, CLI
parsing, layer application, cache publication, and the race detector. Set
`ELFUSE_OCI_NETTEST=1` to add a Docker Hub round trip.
