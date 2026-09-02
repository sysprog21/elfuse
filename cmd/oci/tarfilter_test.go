// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/go-archive"
)

// longCertPath is long enough that a rewritten target outgrows a USTAR header.
const longCertPath = "usr/share/ca-certificates/mozilla/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.crt"

func filterEntries(t *testing.T, entries []tarEntry) map[string]*tar.Header {
	t.Helper()
	return filterEntriesWith(t, testLayerPolicy(t, ""), entries)
}

func filterEntriesWith(t *testing.T, policy *layerPolicy, entries []tarEntry) map[string]*tar.Header {
	t.Helper()
	var filtered bytes.Buffer
	stream := filterLayer(bytes.NewReader(buildLayerTar(t, entries)), policy)
	if _, err := archive.ApplyUncompressedLayer(policy.root.Name(), io.TeeReader(stream, &filtered), unpackOptions()); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&filtered)
	got := map[string]*tar.Header{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got[hdr.Name] = hdr
	}
	return got
}

func TestFilterDropsUnsupportedNodes(t *testing.T) {
	for _, c := range []struct {
		name   string
		layers [][]tarEntry
		want   map[string]bool
	}{
		{name: "devices and FIFOs become whiteouts", layers: [][]tarEntry{{
			{Name: "keep", Body: "x"},
			{Name: "dev-null", Type: tar.TypeChar, Major: 1},
			{Name: "disk", Type: tar.TypeBlock, Major: 8},
			{Name: "pipe", Type: tar.TypeFifo},
		}}, want: map[string]bool{
			"keep": true, "dev-null": false, "disk": false, "pipe": false,
			".wh.dev-null": true, ".wh.disk": true, ".wh.pipe": true,
		}},
		{name: "hardlinks to dropped nodes become whiteouts", layers: [][]tarEntry{{
			{Name: "dev/null", Type: tar.TypeChar, Major: 1},
			{Name: "dev/alias", Link: "dev/null", Type: tar.TypeLink},
			{Name: "/dev/zero", Type: tar.TypeChar, Major: 1},
			{Name: "dev/zero-alias", Link: "dev/zero", Type: tar.TypeLink},
			{Name: "dev/zero-abs", Link: "/dev/zero", Type: tar.TypeLink},
			{Name: "keep", Body: "x"},
			{Name: "keep-alias", Link: "keep", Type: tar.TypeLink},
		}}, want: map[string]bool{
			"dev/null": false, "dev/alias": false, "dev/.wh.alias": true,
			"/dev/zero": false, "dev/zero-alias": false, "dev/zero-abs": false,
			"dev/.wh.zero-alias": true, "dev/.wh.zero-abs": true,
			"keep": true, "keep-alias": true,
		}},
		{name: "drops carry across layers until the path returns", layers: [][]tarEntry{
			{{Name: "dev/null", Type: tar.TypeChar, Major: 1}},
			{{Name: "dev/alias", Link: "dev/null", Type: tar.TypeLink}},
			{{Name: "dev/null", Body: "x"}, {Name: "dev/alias2", Link: "dev/null", Type: tar.TypeLink}},
		}, want: map[string]bool{
			"dev/null": true, "dev/alias2": true,
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			policy := testLayerPolicy(t, "")
			var got map[string]*tar.Header
			captureOutput(t, func() {
				for _, layer := range c.layers {
					got = filterEntriesWith(t, policy, layer)
				}
			})
			for name, want := range c.want {
				if (got[name] != nil) != want {
					t.Errorf("%s: present=%v, want %v", name, got[name] != nil, want)
				}
			}
			for name, hdr := range got {
				if !strings.Contains(name, ".wh.") {
					continue
				}
				if hdr.Typeflag != tar.TypeReg || hdr.Size != 0 {
					t.Errorf("%s: type %c size %d, want an empty regular file", name, hdr.Typeflag, hdr.Size)
				}
			}
		})
	}
}

func TestFilterWarnsOnceAboutDroppedNodes(t *testing.T) {
	_, stderr := captureOutput(t, func() {
		filterEntries(t, []tarEntry{
			{Name: "dev-null", Type: tar.TypeChar, Major: 1},
			{Name: "pipe", Type: tar.TypeFifo},
		})
	})
	mustContain(t, stderr, "dropping device and FIFO entries", "dev-null")
	if strings.Count(stderr, "dropping device") != 1 {
		t.Errorf("warning repeated: %q", stderr)
	}
}

// Ownership is never applied, so a setuid bit would name the invoking user.
func TestFilterClearsSpecialBits(t *testing.T) {
	var got map[string]*tar.Header
	_, stderr := captureOutput(t, func() {
		got = filterEntries(t, []tarEntry{
			{Name: "wall", Body: "x", Mode: 0o2755},
			{Name: "sudoish", Body: "x", Mode: 0o4755},
			{Name: "tmpdir/", Mode: 0o1777},
		})
	})
	for name, want := range map[string]int64{"wall": 0o755, "sudoish": 0o755, "tmpdir/": 0o777} {
		if got[name] == nil || got[name].Mode != want {
			t.Errorf("%s: mode = %o, want %o", name, got[name].Mode, want)
		}
	}
	mustContain(t, stderr, "clearing special permission bits")
}

func TestFilterRewritesAbsoluteSymlinks(t *testing.T) {
	got := filterEntries(t, []tarEntry{
		{Name: "usr/bin/sh", Link: "/bin/busybox"},
		{Name: "bin", Link: "/usr/bin"},
		{Name: "loop", Link: "/"},
		{Name: "etc/rel", Link: "../keep"},
		{Name: "etc/ssl/certs/cert.pem", Link: "/" + longCertPath},
		{Name: "usr/lib/"},
		{Name: "lib", Link: "usr/lib"},
		{Name: "lib/bar", Link: "/usr/lib/foo"},
	})
	for name, want := range map[string]string{
		"usr/bin/sh":             "../../bin/busybox",
		"bin":                    "usr/bin",
		"loop":                   ".",
		"etc/rel":                "../keep",
		"etc/ssl/certs/cert.pem": "../../../" + longCertPath,
		"usr/lib/bar":            "../../usr/lib/foo",
	} {
		if got[name] == nil || got[name].Linkname != want {
			t.Errorf("%s: linkname = %q, want %q", name, got[name].Linkname, want)
		}
	}
}

// go-archive removes a whiteout's whole subtree, so records under it must go
// too, or a later symlink is rewritten against a parent that no longer exists.
func TestFilterForgetsRecordsUnderWhiteouts(t *testing.T) {
	for _, c := range []struct {
		name   string
		second []tarEntry
		link   string
		want   string
	}{
		{name: "plain whiteout", second: []tarEntry{
			{Name: ".wh.lib"},
			{Name: "lib/foo/bar", Link: "/etc/x"},
		}, link: "lib/foo/bar", want: "../../etc/x"},
		{name: "root opaque marker", second: []tarEntry{
			{Name: ".wh..wh..opq"},
			{Name: "lib/foo/bar", Link: "/etc/x"},
		}, link: "lib/foo/bar", want: "../../etc/x"},
		{name: "replaced by a file", second: []tarEntry{
			{Name: "lib", Body: "now a file"},
			{Name: "lib/"},
			{Name: "lib/foo/bar", Link: "/etc/x"},
		}, link: "lib/foo/bar", want: "../../etc/x"},
	} {
		t.Run(c.name, func(t *testing.T) {
			policy := testLayerPolicy(t, "")
			filterEntriesWith(t, policy, []tarEntry{
				{Name: "usr/lib/arm64/"},
				{Name: "lib/foo", Link: "/usr/lib/arm64"},
			})
			got := filterEntriesWith(t, policy, c.second)
			if got[c.link] == nil || got[c.link].Linkname != c.want {
				t.Fatalf("%s: linkname = %v, want %q", c.link, got[c.link], c.want)
			}
		})
	}
}

func TestFilterLayerPromotesRewrittenUSTARSymlink(t *testing.T) {
	target := "/" + longCertPath
	raw := buildLayerTar(t, []tarEntry{{Name: "etc/ssl/certs/cert.pem", Link: target}})

	src := tar.NewReader(bytes.NewReader(raw))
	hdr, err := src.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Format != tar.FormatUSTAR {
		t.Fatalf("source format = %v, want USTAR", hdr.Format)
	}

	var filtered bytes.Buffer
	if _, err := io.Copy(&filtered, filterLayer(bytes.NewReader(raw), testLayerPolicy(t, ""))); err != nil {
		t.Fatal(err)
	}
	out := tar.NewReader(&filtered)
	hdr, err = out.Next()
	if err != nil {
		t.Fatal(err)
	}
	want := "../../../" + longCertPath
	if hdr.Linkname != want {
		t.Fatalf("rewritten target = %q, want %q", hdr.Linkname, want)
	}
}

// The writer rounds a timestamp only when Format is unset, and the reader
// reports a PAX header as PAX, so an untouched header keeps its stamp.
func TestFilterLayerKeepsSubSecondTimestamps(t *testing.T) {
	stamp := time.Unix(1700000000, 700000000)
	raw := buildLayerTar(t, []tarEntry{{Name: "etc/foo", Body: "x", ModTime: stamp}})
	var filtered bytes.Buffer
	if _, err := io.Copy(&filtered, filterLayer(bytes.NewReader(raw), testLayerPolicy(t, ""))); err != nil {
		t.Fatal(err)
	}
	hdr, err := tar.NewReader(&filtered).Next()
	if err != nil {
		t.Fatal(err)
	}
	if !hdr.ModTime.Equal(stamp) {
		t.Fatalf("mtime = %v, want %v", hdr.ModTime, stamp)
	}
}

func testLayerPolicy(t *testing.T, root string) *layerPolicy {
	t.Helper()
	if root == "" {
		root = t.TempDir()
	}
	p, err := newLayerPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
		if err := removeRootfsTree(root); err != nil {
			t.Error(err)
		}
	})
	return p
}

// bigEntries is enough payload that a layer is streamed in many reads.
func bigEntries() []tarEntry {
	var entries []tarEntry
	for i := range 200 {
		entries = append(entries, tarEntry{Name: fmt.Sprintf("f%03d", i), Body: strings.Repeat("x", 64*1024)})
	}
	return entries
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// An extraction failure must stop reading the remaining compressed payload.
func TestApplyLayerReportsMidStreamFailure(t *testing.T) {
	entries := append([]tarEntry{{Name: "bad", Link: "missing", Type: tar.TypeLink}}, bigEntries()...)
	raw := gzipBytes(t, buildLayerTar(t, entries))
	dest := t.TempDir()
	src := &countingReader{r: bytes.NewReader(raw)}
	err := applyLayer(dest, src, testLayerPolicy(t, dest))
	if err == nil {
		t.Fatal("a hardlink to a missing target must fail the layer")
	}
	if src.n >= len(raw) {
		t.Fatalf("read %d of %d bytes after the failure", src.n, len(raw))
	}
}

type cancelOnReadReader struct {
	r      io.Reader
	cancel context.CancelFunc
	fired  bool
}

func (c *cancelOnReadReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if !c.fired {
		c.fired = true
		c.cancel()
	}
	return n, err
}

// Cancellation must land inside a layer, not only between layers.
func TestApplyLayerStopsOnCancellationMidLayer(t *testing.T) {
	raw := gzipBytes(t, buildLayerTar(t, bigEntries()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &cancelOnReadReader{r: bytes.NewReader(raw), cancel: cancel}
	dest := t.TempDir()
	err := applyLayer(dest, contextReader{ctx: ctx, r: src}, testLayerPolicy(t, dest))
	if err == nil {
		t.Fatal("a cancelled context must abort the layer")
	}
	if !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestFilterLayerReadsEntriesOnDemand(t *testing.T) {
	root := t.TempDir()
	p := testLayerPolicy(t, root)
	raw := buildLayerTar(t, []tarEntry{
		{Name: "parent/"},
		{Name: "parent/link", Link: "/target"},
	})
	tr := tar.NewReader(filterLayer(bytes.NewReader(raw), p))
	if _, err := tr.Next(); err != nil {
		t.Fatal(err)
	}
	// Change the parent after consuming the first header. The second header
	// must observe this change even though both entries have empty bodies.
	if err := os.MkdirAll(filepath.Join(root, "real", "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real/dir", filepath.Join(root, "parent")); err != nil {
		t.Fatal(err)
	}
	hdr, err := tr.Next()
	if err != nil || hdr.Name != "real/dir/link" || hdr.Linkname != "../../target" {
		t.Fatalf("second header = %v, %v", hdr, err)
	}
}

func TestFilterLayerStreamsPayloadAndPadding(t *testing.T) {
	for _, size := range []int{0, 1, 511, 512, 513, filterCopyBufferSize * 3} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			body := incompressibleBody(42, size)
			raw := buildLayerTar(t, []tarEntry{{Name: "payload", Body: body}, {Name: "after", Body: "after"}})
			tr := tar.NewReader(filterLayer(bytes.NewReader(raw), testLayerPolicy(t, "")))
			for _, want := range []string{body, "after"} {
				if _, err := tr.Next(); err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(tr)
				if err != nil || string(got) != want {
					t.Fatalf("payload: length %d, %v", len(got), err)
				}
			}
			if _, err := tr.Next(); err != io.EOF {
				t.Fatalf("end of stream = %v", err)
			}
		})
	}
}

func TestFilterLayerRejectsTruncatedPayload(t *testing.T) {
	raw := buildLayerTar(t, []tarEntry{{Name: "file", Body: strings.Repeat("x", 1024)}})
	_, err := io.Copy(io.Discard, filterLayer(bytes.NewReader(raw[:600]), testLayerPolicy(t, "")))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated payload: %v", err)
	}
}

func filteredNames(t *testing.T, raw []byte) []string {
	t.Helper()
	tr := tar.NewReader(filterLayer(bytes.NewReader(raw), testLayerPolicy(t, "")))
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatalf("after %v: %v", names, err)
		}
		names = append(names, hdr.Name)
	}
}

// archive/tar ignores the size field of a header-only entry on both sides, so
// a directory or hardlink written with one carries no body to forward.
func TestFilterLayerIgnoresHeaderOnlySize(t *testing.T) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, hdr := range []*tar.Header{
		{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755, Size: 4096},
		{Name: "etc/orig", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1},
		{Name: "etc/alias", Typeflag: tar.TypeLink, Linkname: "etc/orig", Mode: 0o644, Size: 1},
	} {
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if got := filteredNames(t, raw.Bytes()); len(got) != 3 {
		t.Fatalf("filtered = %v", got)
	}
}

// The writer refuses a regular file named with a trailing slash, which the
// reader passes through, so the filter cleans the name.
func TestFilterLayerCleansTrailingSlashOnRegularFile(t *testing.T) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	if err := tw.WriteHeader(&tar.Header{Name: "etc/foo", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	b := raw.Bytes()
	copy(b, "etc/foo/\x00")
	sum := 0
	for i, c := range b[:512] {
		if i >= 148 && i < 156 {
			sum += ' '
		} else {
			sum += int(c)
		}
	}
	copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
	hdr, err := tar.NewReader(bytes.NewReader(b)).Next()
	if err != nil || hdr.Name != "etc/foo/" || hdr.Typeflag != tar.TypeReg {
		t.Fatalf("fixture = %+v, %v", hdr, err)
	}
	if got := filteredNames(t, b); len(got) != 1 || got[0] != "etc/foo" {
		t.Fatalf("filtered = %v", got)
	}
}
