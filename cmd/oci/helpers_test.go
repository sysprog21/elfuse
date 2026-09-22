// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type tarEntry struct {
	Name    string
	Body    string
	Link    string
	Mode    int64
	Type    byte
	Major   int64
	ModTime time.Time
}

func buildLayerTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.Name, Mode: e.Mode, Size: int64(len(e.Body)), Typeflag: tar.TypeReg, ModTime: e.ModTime}
		if hdr.Mode == 0 {
			hdr.Mode = 0o644
		}
		// tar.Writer rounds ModTime to whole seconds unless Format is set, and
		// only PAX keeps the fraction.
		if e.ModTime.Nanosecond() != 0 {
			hdr.Format = tar.FormatPAX
		}
		switch {
		case e.Type != 0:
			hdr.Typeflag = e.Type
			hdr.Size = 0
			hdr.Linkname = e.Link
			hdr.Devmajor = e.Major
		case e.Link != "":
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = e.Link
			hdr.Size = 0
		case e.Name[len(e.Name)-1] == '/':
			hdr.Typeflag = tar.TypeDir
			if e.Mode == 0 {
				hdr.Mode = 0o755
			}
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.Body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var z bytes.Buffer
	zw, err := gzip.NewWriterLevel(&z, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return z.Bytes()
}

type testImage struct {
	platform ocispec.Platform
	layers   [][]tarEntry
}

func pushTestImage(t *testing.T, s *store, img testImage) string {
	t.Helper()
	if img.platform.OS == "" {
		img.platform = defaultPlatform
	}
	if len(img.layers) == 0 {
		img.layers = [][]tarEntry{{{Name: "hello", Body: "world"}}}
	}

	var layers []v1.Descriptor
	var diffIDs []v1.Hash
	for _, entries := range img.layers {
		raw := buildLayerTar(t, entries)
		gz := gzipBytes(t, raw)
		layers = append(layers, pushBlob(t, s, types.OCILayer, gz))
		diffID, _, err := v1.SHA256(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		diffIDs = append(diffIDs, diffID)
	}

	cfg := v1.ConfigFile{
		Architecture: img.platform.Architecture,
		OS:           img.platform.OS,
		Variant:      img.platform.Variant,
		RootFS:       v1.RootFS{Type: "layers", DiffIDs: diffIDs},
	}
	cfgDesc := pushBlob(t, s, types.OCIConfigJSON, mustJSON(t, cfg))
	manifest := v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config:        cfgDesc,
		Layers:        layers,
	}
	return pushBlob(t, s, types.OCIManifestSchema1, mustJSON(t, manifest)).Digest.String()
}

func pushBlob(t *testing.T, s *store, media types.MediaType, b []byte) v1.Descriptor {
	t.Helper()
	desc, err := s.writeBlobBytes(context.Background(), media, b)
	if err != nil {
		t.Fatal(err)
	}
	return desc
}

func storeWithImage(t *testing.T, ref string, img testImage) (*store, string) {
	t.Helper()
	s := tempStore(t)
	if img.platform.OS == "" {
		img.platform = defaultPlatform
	}
	digest := pushTestImage(t, s, img)
	pinImage(t, s, ref, img.platform, digest)
	return s, digest
}

func pinImage(t *testing.T, s *store, ref string, platform ocispec.Platform, digest string) {
	t.Helper()
	if err := pinImageError(s, ref, platform, digest); err != nil {
		t.Fatal(err)
	}
}

func pinImageError(s *store, ref string, platform ocispec.Platform, digest string) error {
	ctx := context.Background()
	hash, err := v1.NewHash(digest)
	if err != nil {
		return err
	}
	b, err := s.blobBytes(hash)
	if err != nil {
		return err
	}
	parsed, err := normalizeRef(ref)
	if err != nil {
		return err
	}
	desc := v1.Descriptor{MediaType: types.OCIManifestSchema1, Digest: hash, Size: int64(len(b))}
	return s.withLock(ctx, func() error {
		return s.pinLocked(ctx, parsed.Name(), platform, desc)
	})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeShellStub(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func prependPath(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func tempStore(t *testing.T) *store {
	t.Helper()
	ctx := context.Background()
	s, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ensureLayout(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

func captureOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	or, ow, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	er, ew, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = ow, ew
	outCh := make(chan string, 1)
	errCh := make(chan string, 1)
	go func() { var b bytes.Buffer; _, _ = io.Copy(&b, or); outCh <- b.String() }()
	go func() { var b bytes.Buffer; _, _ = io.Copy(&b, er); errCh <- b.String() }()
	defer func() {
		os.Stdout, os.Stderr = oldOut, oldErr
		ow.Close()
		ew.Close()
		or.Close()
		er.Close()
	}()
	fn()
	ow.Close()
	ew.Close()
	return <-outCh, <-errCh
}

func mustContain(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func manifestOf(t *testing.T, s *store, digest string) ocispec.Manifest {
	t.Helper()
	manifest, err := s.manifestFor(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func runCaptured(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	_, stderr := captureOutput(t, func() { err = run(args) })
	return stderr, err
}

func unpackFresh(t *testing.T, s *store, digest string) string {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "rootfs")
	if err := unpackFreshTo(t, s, digest, dest, false); err != nil {
		t.Fatal(err)
	}
	return dest
}

func unpackFreshTo(t *testing.T, s *store, digest, dest string, cached bool) (err error) {
	t.Helper()
	t.Cleanup(func() { _ = removeRootfsTree(dest) })
	captureOutput(t, func() {
		err = unpackImageFresh(context.Background(), s, manifestOf(t, s, digest), dest, cached)
	})
	return err
}

// incompressibleBody returns seeded random bytes, which gzip cannot shrink.
func incompressibleBody(seed, n int) string {
	r := rand.New(rand.NewSource(int64(seed)))
	b := make([]byte, n)
	r.Read(b)
	return string(b)
}
