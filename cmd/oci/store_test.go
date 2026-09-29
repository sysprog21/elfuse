// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type cancelReadCloser struct {
	cancel context.CancelFunc
	done   bool
}

func (r *cancelReadCloser) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	r.cancel()
	p[0] = 'x'
	return 1, nil
}

func (r *cancelReadCloser) Close() error { return nil }

func TestPinsPerPlatform(t *testing.T) {
	s := tempStore(t)
	arm := ocispec.Platform{OS: "linux", Architecture: "arm64"}
	amd := ocispec.Platform{OS: "linux", Architecture: "amd64"}
	armDigest := pushTestImage(t, s, testImage{platform: arm})
	amdDigest := pushTestImage(t, s, testImage{platform: amd})
	pinImage(t, s, "alpine:3", arm, armDigest)
	pinImage(t, s, "docker.io/library/alpine:3", amd, amdDigest)
	for _, tc := range []struct {
		platform ocispec.Platform
		want     string
	}{{arm, armDigest}, {amd, amdDigest}} {
		index, err := s.rootIndex()
		if err != nil {
			t.Fatal(err)
		}
		b, err := s.blobBytes(index.Manifests[0].Digest)
		if err != nil {
			t.Fatal(err)
		}
		var nested v1.IndexManifest
		if err := json.Unmarshal(b, &nested); err != nil {
			t.Fatal(err)
		}
		found := ""
		for _, desc := range nested.Manifests {
			if samePlatform(desc.Platform, tc.platform) {
				found = desc.Digest.String()
			}
		}
		if found != tc.want {
			t.Fatalf("pin for %s = %q, want %q", platformString(tc.platform), found, tc.want)
		}
	}
}

func TestRootIndexNamesNestedIndex(t *testing.T) {
	s, digest := storeWithImage(t, "alpine:3", testImage{})
	index, err := s.rootIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Manifests) != 1 {
		t.Fatalf("root descriptors = %d", len(index.Manifests))
	}
	desc := index.Manifests[0]
	if desc.MediaType != types.OCIImageIndex || desc.Annotations[refNameAnnotation] != "index.docker.io/library/alpine:3" {
		t.Fatalf("root descriptor = %+v", desc)
	}
	b, err := s.blobBytes(desc.Digest)
	if err != nil {
		t.Fatal(err)
	}
	var nested v1.IndexManifest
	if err := json.Unmarshal(b, &nested); err != nil {
		t.Fatal(err)
	}
	if len(nested.Manifests) != 1 || nested.Manifests[0].Digest.String() != digest || !samePlatform(nested.Manifests[0].Platform, defaultPlatform) {
		t.Fatalf("nested index = %+v", nested)
	}
}

func TestDigestForErrorKinds(t *testing.T) {
	s := tempStore(t)
	_, err := s.digestFor("absent:1", defaultPlatform)
	if !errors.Is(err, errNotPulled) || !strings.Contains(err.Error(), "elfuse-oci pull") {
		t.Fatalf("missing image error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.root, "index.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.digestFor("absent:1", defaultPlatform); err == nil || errors.Is(err, errNotPulled) {
		t.Fatalf("corrupt index error = %v", err)
	}
}

func TestManifestRoundTrip(t *testing.T) {
	s, digest := storeWithImage(t, "fix:1", testImage{})
	manifest, err := s.manifestFor(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Layers) != 1 || manifest.Config.MediaType != ocispec.MediaTypeImageConfig {
		t.Fatalf("manifest = %+v", manifest)
	}
}

func TestManifestForRejectsInvalidManifest(t *testing.T) {
	s := tempStore(t)
	for _, body := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"schemaVersion":1,"config":{"digest":"sha256:` + strings.Repeat("0", 64) + `"}}`),
	} {
		desc := pushBlob(t, s, types.OCIManifestSchema1, body)
		if _, err := s.manifestFor(context.Background(), desc.Digest.String()); err == nil {
			t.Fatalf("manifest %s must fail validation", body)
		}
	}
}

func TestPinConcurrentWritersKeepAllEntries(t *testing.T) {
	s := tempStore(t)
	digest := pushTestImage(t, s, testImage{})
	const count = 8
	var wg sync.WaitGroup
	errCh := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errCh <- pinImageError(s, "img"+string(rune('a'+i))+":1", defaultPlatform, digest)
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	index, err := s.rootIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Manifests) != count {
		t.Fatalf("root descriptors = %d, want %d", len(index.Manifests), count)
	}
}

func TestBlobLayout(t *testing.T) {
	s := tempStore(t)
	desc := pushBlob(t, s, types.OCIConfigJSON, []byte("{}"))
	fi, err := os.Stat(filepath.Join(s.root, "blobs", "sha256", desc.Digest.Hex))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o222 != 0 {
		t.Fatalf("blob mode %v has write bits", fi.Mode())
	}
	path := filepath.Join(s.root, "blobs", "sha256", desc.Digest.Hex)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.writeBlobBytes(context.Background(), types.OCIConfigJSON, []byte("{}")); err == nil {
		t.Fatal("an existing blob with the wrong content must fail")
	}
	for _, name := range []string{markerName, "oci-layout", "index.json"} {
		if _, err := os.Stat(filepath.Join(s.root, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestWriteBlobStopsOnCancellation(t *testing.T) {
	s := tempStore(t)
	body := []byte("xx")
	hash, size, err := v1.SHA256(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	err = s.writeBlob(ctx, v1.Descriptor{MediaType: types.OCIConfigJSON, Digest: hash, Size: size}, &cancelReadCloser{cancel: cancel})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("write error = %v", err)
	}
	path := filepath.Join(s.root, "blobs", hash.Algorithm, hash.Hex)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("canceled blob exists: %v", err)
	}
}

func TestPinLockedStopsOnCancellation(t *testing.T) {
	s := tempStore(t)
	digest := pushTestImage(t, s, testImage{})
	hash, err := v1.NewHash(digest)
	if err != nil {
		t.Fatal(err)
	}
	body, err := s.blobBytes(hash)
	if err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(s.root, "index.json")
	before, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	desc := v1.Descriptor{MediaType: types.OCIManifestSchema1, Digest: hash, Size: int64(len(body))}
	if err := s.pinLocked(ctx, "index.docker.io/library/canceled:1", defaultPlatform, desc); !errors.Is(err, context.Canceled) {
		t.Fatalf("pin error = %v", err)
	}
	after, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("canceled pin changed index.json")
	}
}

func TestStoreRefusesLegacyAndForeignDirectories(t *testing.T) {
	for _, name := range []string{"refs.json", "foreign"} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, name), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		s, err := openStore(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.withLock(context.Background(), func() error {
			return s.ensureLayoutLocked(context.Background())
		}); err == nil {
			t.Fatalf("directory containing %s must be refused", name)
		}
	}
}

func TestStoreAcceptsSymlinkAndRemovesMetadataTemps(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"..elfuse-oci-store.tmp.1.1", ".oci-layout.tmp.1.1", ".index.json.tmp.1.1"} {
		if err := os.WriteFile(filepath.Join(target, name), []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(parent, "store")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ensureLayout(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"..elfuse-oci-store.tmp.1.1", ".oci-layout.tmp.1.1", ".index.json.tmp.1.1"} {
		if _, err := os.Stat(filepath.Join(target, name)); !os.IsNotExist(err) {
			t.Fatalf("stale temporary file %s remains: %v", name, err)
		}
	}
}

func TestStoreFilesArePrivate(t *testing.T) {
	s := tempStore(t)
	desc := pushBlob(t, s, types.OCIConfigJSON, []byte("{}"))
	paths := map[string]os.FileMode{
		s.root:                         0o700,
		filepath.Join(s.root, "blobs"): 0o700,
		filepath.Join(s.root, "blobs", desc.Digest.Algorithm):                  0o700,
		filepath.Join(s.root, metadataLockName):                                0o600,
		filepath.Join(s.root, markerName):                                      0o600,
		filepath.Join(s.root, "oci-layout"):                                    0o600,
		filepath.Join(s.root, "index.json"):                                    0o600,
		filepath.Join(s.root, "blobs", desc.Digest.Algorithm, desc.Digest.Hex): 0o400,
	}
	for path, want := range paths {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", path, got, want)
		}
	}
}

func TestPinSortAcceptsPlatformlessExistingChild(t *testing.T) {
	s := tempStore(t)
	digest := pushTestImage(t, s, testImage{})
	hash, err := v1.NewHash(digest)
	if err != nil {
		t.Fatal(err)
	}
	nested := v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests:     []v1.Descriptor{{MediaType: types.OCIManifestSchema1, Digest: hash}},
	}
	nestedDesc, err := s.writeBlobBytes(context.Background(), types.OCIImageIndex, mustJSON(t, nested))
	if err != nil {
		t.Fatal(err)
	}
	nestedDesc.Annotations = map[string]string{refNameAnnotation: "index.docker.io/library/nil:1"}
	root := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{nestedDesc}}
	if err := replaceFile(context.Background(), s.root, "index.json", append(mustJSON(t, root), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	pinImage(t, s, "nil:1", defaultPlatform, digest)
}

func TestWithLockEndsWithContext(t *testing.T) {
	s := tempStore(t)
	if filepath.Dir(s.lockPath()) != s.root {
		t.Fatalf("lock path %s is outside store", s.lockPath())
	}
	held, err := acquireFlock(context.Background(), s.lockPath())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*flockPoll)
	defer cancel()
	err = s.withLock(ctx, func() error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
	held.Close()
	if err := s.withLock(context.Background(), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestWithLockRefusesExpiredContext(t *testing.T) {
	s := tempStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ran := false
	err := s.withLock(ctx, func() error { ran = true; return nil })
	if !errors.Is(err, context.Canceled) || ran {
		t.Fatalf("error = %v, ran = %v", err, ran)
	}
}

func TestCacheDirRejectsSymlinkedParent(t *testing.T) {
	good := "sha256:" + strings.Repeat("a", 64)
	for _, rel := range []string{cacheRootfs, filepath.Join(cacheRootfs, "sha256")} {
		s := tempStore(t)
		p := filepath.Join(s.root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.Symlink(t.TempDir(), p); err != nil {
			t.Fatal(err)
		}
		_, err := s.cacheDir(cacheRootfs, good)
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Errorf("%s: err = %v, want a symlink refusal", rel, err)
		}
	}
}

func TestCacheDirRejectsOddDigests(t *testing.T) {
	s := tempStore(t)
	for _, bad := range []string{"sha512:" + strings.Repeat("a", 128), "sha256:short", "zzz",
		"sha256:" + strings.Repeat("g", 64)} {
		if _, err := s.cacheDir(cacheRootfs, bad); err == nil {
			t.Errorf("digest %q must be rejected as a cache key", bad)
		}
	}
}

func TestRefuseRootfsInStore(t *testing.T) {
	s := tempStore(t)
	for _, rootfs := range []string{s.root, filepath.Join(s.root, "rootfs", "x")} {
		if err := refuseRootfsInStore(s.root, rootfs); err == nil ||
			!strings.Contains(err.Error(), "inside the store") {
			t.Errorf("%s: err = %v, want a refusal", rootfs, err)
		}
	}
	if err := refuseRootfsInStore(s.root, filepath.Dir(s.root)); err == nil ||
		!strings.Contains(err.Error(), "contains the store") {
		t.Errorf("store parent: err = %v, want a refusal", err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, rootfs := range []string{"", t.TempDir(), filepath.Join(file, "child")} {
		if err := refuseRootfsInStore(s.root, rootfs); err != nil {
			t.Errorf("%q: err = %v, want acceptance", rootfs, err)
		}
	}
}

// A store that pull would refuse is refused for reading, and a mistyped path
// is not created.
func TestOpenStoreForReadRefusals(t *testing.T) {
	legacy := t.TempDir()
	if err := os.WriteFile(filepath.Join(legacy, "refs.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openStoreForRead(legacy); err == nil || !strings.Contains(err.Error(), "legacy refs.json") {
		t.Errorf("legacy store: err = %v, want the legacy refusal", err)
	}

	bare := t.TempDir()
	if err := os.WriteFile(filepath.Join(bare, "index.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openStoreForRead(bare); err == nil || !strings.Contains(err.Error(), "not an elfuse OCI store") {
		t.Errorf("marker-less store: err = %v, want a format refusal", err)
	}

	s := tempStore(t)
	if err := os.WriteFile(filepath.Join(s.root, "oci-layout"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openStoreForRead(s.root); err == nil || !strings.Contains(err.Error(), "corrupt oci-layout") {
		t.Errorf("malformed oci-layout: err = %v, want a format refusal", err)
	}
	if err := os.WriteFile(filepath.Join(s.root, markerName), []byte("2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openStoreForRead(s.root); err == nil || !strings.Contains(err.Error(), "unsupported format marker") {
		t.Errorf("newer marker: err = %v, want a format refusal", err)
	}

	missing := filepath.Join(t.TempDir(), "absent")
	if _, err := openStoreForRead(missing); err == nil {
		t.Fatal("a missing store must fail")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Error("opening for read must not create the store directory")
	}
}
