// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	markerName        = ".elfuse-oci-store"
	markerContents    = "1\n"
	metadataLockName  = ".lock"
	refNameAnnotation = "org.opencontainers.image.ref.name"
)

var (
	errNoMarker  = errors.New("no store format marker")
	errNotPulled = errors.New("not pulled")
)

type store struct {
	root string
}

func openStore(root string) (*store, error) {
	root = filepath.Clean(root)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	fi, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("store: %s is not a directory", root)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, err
	}
	return &store{root: root}, nil
}

func (s *store) lockPath() string { return filepath.Join(s.root, metadataLockName) }

// openStoreForRead creates and repairs nothing, so a mistyped --store leaves
// nothing behind.
func openStoreForRead(root string) (*store, error) {
	root = filepath.Clean(root)
	fi, err := os.Stat(root)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("store: %s does not exist", root)
	}
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("store: %s is not a directory", root)
	}
	s := &store{root: root}
	if err := s.checkLayout(); err != nil {
		if errors.Is(err, errNoMarker) {
			return nil, fmt.Errorf("store: %s is not an elfuse OCI store", root)
		}
		return nil, err
	}
	if b, err := os.ReadFile(filepath.Join(root, "oci-layout")); err == nil {
		if err := checkJSON("oci-layout", b); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

// checkLayout validates the store format without writing. errNoMarker means the
// directory carries no marker, which pull may create and a reader must refuse.
func (s *store) checkLayout() error {
	marker, err := os.ReadFile(filepath.Join(s.root, markerName))
	if os.IsNotExist(err) {
		if _, legacyErr := os.Lstat(filepath.Join(s.root, "refs.json")); legacyErr == nil {
			return fmt.Errorf("store: legacy refs.json layout; remove the store and pull again")
		}
		return errNoMarker
	}
	if err != nil {
		return err
	}
	if string(marker) != markerContents {
		return fmt.Errorf("store: unsupported format marker %q", strings.TrimSpace(string(marker)))
	}
	return nil
}

const cacheRootfs = "rootfs"

func (s *store) cacheBase(kind string) string {
	return filepath.Join(s.root, kind, "sha256")
}

func digestHex(dgst string) (string, error) {
	d, err := v1.NewHash(dgst)
	if err != nil || d.Algorithm != "sha256" {
		return "", fmt.Errorf("store: unsupported digest %q for a cache key", dgst)
	}
	return d.Hex, nil
}

func (s *store) cacheDir(kind, dgst string) (string, error) {
	h, err := digestHex(dgst)
	if err != nil {
		return "", err
	}
	for _, p := range []string{filepath.Join(s.root, kind), s.cacheBase(kind)} {
		if err := rejectSymlink(p); err != nil {
			return "", err
		}
	}
	return filepath.Join(s.cacheBase(kind), h), nil
}

func rejectSymlink(path string) error {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to use it as a cache directory", path)
	}
	return nil
}

func insideStore(storeRoot, path string) bool {
	abs := resolvedAbs(path)
	absStore := resolvedAbs(storeRoot)
	if abs == "" || absStore == "" {
		return true
	}
	storeInfo, err := os.Stat(absStore)
	if err != nil {
		return true
	}
	// Filesystem identity catches case aliases on APFS. A tail that
	// cannot be stat'ed is checked through its ancestors.
	for candidate := abs; ; candidate = filepath.Dir(candidate) {
		if info, err := os.Stat(candidate); err == nil && os.SameFile(storeInfo, info) {
			return true
		}
		if filepath.Dir(candidate) == candidate {
			return false
		}
	}
}

func refuseRootfsInStore(storeRoot, rootfs string) error {
	if rootfs != "" && insideStore(storeRoot, rootfs) {
		return fmt.Errorf("unpack: --rootfs %s is inside the store; drop --rootfs for the managed cache", rootfs)
	}
	if _, err := os.Stat(rootfs); err == nil && insideStore(rootfs, storeRoot) {
		return fmt.Errorf("unpack: --rootfs %s contains the store", rootfs)
	}
	return nil
}

func resolvedAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	rest := ""
	for p := abs; ; {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return abs
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = parent
	}
}

func (s *store) withLock(ctx context.Context, fn func() error) error {
	l, err := acquireFlock(ctx, s.lockPath())
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer l.Close()
	return fn()
}

func (s *store) ensureLayout(ctx context.Context) error {
	return s.withLock(ctx, func() error { return s.ensureLayoutLocked(ctx) })
}

func isMetadataTemp(name string) bool {
	for _, target := range []string{markerName, "oci-layout", "index.json"} {
		if strings.HasPrefix(name, "."+target+".tmp.") {
			return true
		}
	}
	return false
}

func (s *store) ensureLayoutLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.checkLayout()
	if errors.Is(err, errNoMarker) {
		entries, readErr := os.ReadDir(s.root)
		if readErr != nil {
			return readErr
		}
		for _, entry := range entries {
			if entry.Name() == metadataLockName {
				continue
			}
			if !isMetadataTemp(entry.Name()) || entry.IsDir() {
				return fmt.Errorf("store: %s is not an elfuse OCI store", s.root)
			}
			if err := os.Remove(filepath.Join(s.root, entry.Name())); err != nil {
				return err
			}
		}
		if err := replaceFile(ctx, s.root, markerName, []byte(markerContents), 0o600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := ensureJSONFile(ctx, filepath.Join(s.root, "oci-layout"), []byte("{\"imageLayoutVersion\":\"1.0.0\"}\n")); err != nil {
		return err
	}
	empty := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex}
	b, err := json.MarshalIndent(empty, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return ensureJSONFile(ctx, filepath.Join(s.root, "index.json"), b)
}

func ensureJSONFile(ctx context.Context, path string, initial []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return replaceFile(ctx, filepath.Dir(path), filepath.Base(path), initial, 0o600)
	}
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return checkJSON(filepath.Base(path), b)
}

func checkJSON(name string, b []byte) error {
	var value any
	if err := json.Unmarshal(b, &value); err != nil {
		return fmt.Errorf("store: corrupt %s: %w", name, err)
	}
	return nil
}

func replaceFile(ctx context.Context, dir, name string, content []byte, mode os.FileMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tmp := fmt.Sprintf(".%s.tmp.%d.%d", name, os.Getpid(), time.Now().UnixNano())
	tmpPath := filepath.Join(dir, tmp)
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	defer f.Close()
	if _, err := f.Write(content); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func (s *store) rootIndex() (v1.IndexManifest, error) {
	var index v1.IndexManifest
	b, err := os.ReadFile(filepath.Join(s.root, "index.json"))
	if err != nil {
		return index, err
	}
	if err := json.Unmarshal(b, &index); err != nil {
		return index, fmt.Errorf("store: corrupt index.json: %w", err)
	}
	if index.SchemaVersion != 2 {
		return index, fmt.Errorf("store: index.json schema version is %d", index.SchemaVersion)
	}
	return index, nil
}

func (s *store) blobBytes(hash v1.Hash) ([]byte, error) {
	b, err := layout.Path(s.root).Bytes(hash)
	if err != nil {
		return nil, fmt.Errorf("store: read blob %s: %w", hash, err)
	}
	return b, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// ensurePrivateDir creates a per-algorithm cache directory and sets the
// store's mode on it and on its kind directory.
func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	for _, p := range []string{path, filepath.Dir(path)} {
		if err := os.Chmod(p, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	err = d.Sync()
	if closeErr := d.Close(); err == nil {
		err = closeErr
	}
	return err
}

func (s *store) blob(hash v1.Hash) (io.ReadCloser, error) {
	r, err := layout.Path(s.root).Blob(hash)
	if err != nil {
		return nil, fmt.Errorf("store: read blob %s: %w", hash, err)
	}
	return r, nil
}

func (s *store) writeBlob(ctx context.Context, desc v1.Descriptor, r io.ReadCloser) error {
	defer r.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Join(s.root, "blobs", desc.Digest.Algorithm)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, desc.Digest.Hex)
	if f, err := os.Open(path); err == nil {
		fi, statErr := f.Stat()
		if err := ctx.Err(); err != nil {
			f.Close()
			return err
		}
		hasher, hashErr := v1.Hasher(desc.Digest.Algorithm)
		if hashErr == nil {
			_, hashErr = io.Copy(hasher, contextReader{ctx: ctx, r: f})
		}
		closeErr := f.Close()
		got := v1.Hash{Algorithm: desc.Digest.Algorithm}
		if hashErr == nil {
			got.Hex = hex.EncodeToString(hasher.Sum(nil))
		}
		if statErr != nil || hashErr != nil || closeErr != nil || got != desc.Digest || fi.Size() != desc.Size {
			return fmt.Errorf("store: corrupt blob %s", desc.Digest)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".blob-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	hasher, err := v1.Hasher(desc.Digest.Algorithm)
	if err != nil {
		tmp.Close()
		return err
	}
	n, err := io.Copy(io.MultiWriter(tmp, hasher), contextReader{ctx: ctx, r: r})
	if err != nil {
		tmp.Close()
		return err
	}
	got := v1.Hash{Algorithm: desc.Digest.Algorithm, Hex: hex.EncodeToString(hasher.Sum(nil))}
	if n != desc.Size || got != desc.Digest {
		tmp.Close()
		return fmt.Errorf("store: blob %s content mismatch", desc.Digest)
	}
	if err := ctx.Err(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o400); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	for _, path := range []string{dir, filepath.Join(s.root, "blobs"), s.root} {
		if err := syncDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func (s *store) writeBlobBytes(ctx context.Context, media types.MediaType, b []byte) (v1.Descriptor, error) {
	hash, size, err := v1.SHA256(bytes.NewReader(b))
	if err != nil {
		return v1.Descriptor{}, err
	}
	desc := v1.Descriptor{MediaType: media, Digest: hash, Size: size}
	return desc, s.writeBlob(ctx, desc, io.NopCloser(bytes.NewReader(b)))
}

func (s *store) publishImage(ctx context.Context, img v1.Image, platform ocispec.Platform) (v1.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return v1.Descriptor{}, err
	}
	layers, err := img.Layers()
	if err != nil {
		return v1.Descriptor{}, err
	}
	for _, layer := range layers {
		if err := ctx.Err(); err != nil {
			return v1.Descriptor{}, err
		}
		digest, err := layer.Digest()
		if err != nil {
			return v1.Descriptor{}, err
		}
		size, err := layer.Size()
		if err != nil {
			return v1.Descriptor{}, err
		}
		media, err := layer.MediaType()
		if err != nil {
			return v1.Descriptor{}, err
		}
		r, err := layer.Compressed()
		if err != nil {
			return v1.Descriptor{}, err
		}
		if err := s.writeBlob(ctx, v1.Descriptor{MediaType: media, Digest: digest, Size: size}, r); err != nil {
			return v1.Descriptor{}, err
		}
	}
	config, err := img.RawConfigFile()
	if err != nil {
		return v1.Descriptor{}, err
	}
	configHash, err := img.ConfigName()
	if err != nil {
		return v1.Descriptor{}, err
	}
	if err := s.writeBlob(ctx, v1.Descriptor{MediaType: types.OCIConfigJSON, Digest: configHash, Size: int64(len(config))}, io.NopCloser(bytes.NewReader(config))); err != nil {
		return v1.Descriptor{}, err
	}
	manifest, err := img.RawManifest()
	if err != nil {
		return v1.Descriptor{}, err
	}
	digest, err := img.Digest()
	if err != nil {
		return v1.Descriptor{}, err
	}
	media, err := img.MediaType()
	if err != nil {
		return v1.Descriptor{}, err
	}
	desc := v1.Descriptor{MediaType: media, Digest: digest, Size: int64(len(manifest)), Platform: toV1Platform(platform)}
	if err := s.writeBlob(ctx, desc, io.NopCloser(bytes.NewReader(manifest))); err != nil {
		return v1.Descriptor{}, err
	}
	return desc, nil
}

func toV1Platform(p ocispec.Platform) *v1.Platform {
	return &v1.Platform{OS: p.OS, Architecture: p.Architecture, Variant: p.Variant}
}

func samePlatform(a *v1.Platform, b ocispec.Platform) bool {
	return a != nil && a.OS == b.OS && a.Architecture == b.Architecture && a.Variant == b.Variant
}

func (s *store) pinLocked(ctx context.Context, ref string, platform ocispec.Platform, manifest v1.Descriptor) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	index, err := s.rootIndex()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	nested, err := s.nestedIndex(index, ref)
	if err != nil {
		return err
	}
	kept := nested.Manifests[:0]
	for _, desc := range nested.Manifests {
		if !samePlatform(desc.Platform, platform) {
			kept = append(kept, desc)
		}
	}
	manifest.Platform = toV1Platform(platform)
	nested.Manifests = append(kept, manifest)
	sort.Slice(nested.Manifests, func(i, j int) bool {
		return platformKey(nested.Manifests[i].Platform) < platformKey(nested.Manifests[j].Platform)
	})
	nestedBytes, err := json.MarshalIndent(nested, "", "  ")
	if err != nil {
		return err
	}
	nestedBytes = append(nestedBytes, '\n')
	nestedDesc, err := s.writeBlobBytes(ctx, types.OCIImageIndex, nestedBytes)
	if err != nil {
		return err
	}
	nestedDesc.Annotations = map[string]string{refNameAnnotation: ref}
	root := index.Manifests[:0]
	for _, desc := range index.Manifests {
		if desc.Annotations[refNameAnnotation] != ref {
			root = append(root, desc)
		}
	}
	index.Manifests = append(root, nestedDesc)
	sort.Slice(index.Manifests, func(i, j int) bool {
		return index.Manifests[i].Annotations[refNameAnnotation] < index.Manifests[j].Annotations[refNameAnnotation]
	})
	b, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return replaceFile(ctx, s.root, "index.json", b, 0o600)
}

func platformKey(platform *v1.Platform) string {
	if platform == nil {
		return ""
	}
	return platform.String()
}

func (s *store) nestedIndex(index v1.IndexManifest, name string) (v1.IndexManifest, error) {
	nested := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex}
	for _, desc := range index.Manifests {
		if desc.Annotations[refNameAnnotation] != name {
			continue
		}
		b, err := s.blobBytes(desc.Digest)
		if err != nil {
			return nested, err
		}
		if err := json.Unmarshal(b, &nested); err != nil {
			return nested, fmt.Errorf("store: parse index for %s: %w", name, err)
		}
	}
	return nested, nil
}

func (s *store) digestFor(ref string, platform ocispec.Platform) (string, error) {
	parsed, err := normalizeRef(ref)
	if err != nil {
		return "", err
	}
	index, err := s.rootIndex()
	if os.IsNotExist(err) {
		return "", notPulledError(ref, platform)
	}
	if err != nil {
		return "", err
	}
	nested, err := s.nestedIndex(index, parsed.Name())
	if err != nil {
		return "", err
	}
	for _, child := range nested.Manifests {
		if samePlatform(child.Platform, platform) {
			return child.Digest.String(), nil
		}
	}
	return "", notPulledError(ref, platform)
}

func notPulledError(ref string, platform ocispec.Platform) error {
	p := platformString(platform)
	return fmt.Errorf("store: %q %w for %s (run elfuse-oci pull --platform %s %s first)", ref, errNotPulled, p, p, ref)
}

func (s *store) manifestFor(ctx context.Context, digest string) (ocispec.Manifest, error) {
	var manifest ocispec.Manifest
	if err := ctx.Err(); err != nil {
		return manifest, err
	}
	hash, err := v1.NewHash(digest)
	if err != nil {
		return manifest, fmt.Errorf("store: manifest %s: %w", digest, err)
	}
	b, err := s.blobBytes(hash)
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		return manifest, fmt.Errorf("store: parse manifest %s: %w", digest, err)
	}
	if manifest.SchemaVersion != 2 || manifest.Config.Digest == "" {
		return manifest, fmt.Errorf("store: invalid manifest %s", digest)
	}
	return manifest, nil
}

func (s *store) loadRef(ctx context.Context, ref string, platform ocispec.Platform) (string, ocispec.Manifest, error) {
	d, err := s.digestFor(ref, platform)
	if err != nil {
		return "", ocispec.Manifest{}, err
	}
	m, err := s.manifestFor(ctx, d)
	return d, m, err
}
