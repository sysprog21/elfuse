// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUnpackAppliesWhiteoutsAcrossLayers(t *testing.T) {
	s, d := storeWithImage(t, "wh:1", testImage{layers: [][]tarEntry{
		{{Name: "a/"}, {Name: "a/keep", Body: "k"}, {Name: "a/gone", Body: "g"},
			{Name: "a/sub/"}, {Name: "a/sub/old", Body: "o"}, {Name: "a/dev", Body: "d"}},
		{{Name: "a/.wh.gone"}, {Name: "a/sub/.wh..wh..opq"}, {Name: "a/sub/new", Body: "n"},
			{Name: "a/dev", Type: tar.TypeChar, Major: 1}},
		{{Name: "a/devlink", Link: "a/dev", Type: tar.TypeLink}},
	}})
	dest := unpackFresh(t, s, d)
	for p, want := range map[string]bool{
		"a/keep": true, "a/gone": false,
		"a/sub/old": false, "a/sub/new": true,
		"a/.wh.gone": false,
		"a/dev":      false, "a/.wh.dev": false, "a/devlink": false,
	} {
		_, err := os.Lstat(filepath.Join(dest, p))
		if want != (err == nil) {
			t.Errorf("%s: present=%v, want %v", p, err == nil, want)
		}
	}
	b, err := os.ReadFile(filepath.Join(dest, "a/sub/new"))
	if err != nil || string(b) != "n" {
		t.Fatalf("a/sub/new = %q, %v", b, err)
	}
}

// A hardlink to a dropped device must whiteout its own path, or a file the
// image meant to replace survives from the layer below.
func TestUnpackHardlinkToDroppedDeviceRemovesLowerFile(t *testing.T) {
	s, d := storeWithImage(t, "hlwh:1", testImage{layers: [][]tarEntry{
		{{Name: "dev/"}, {Name: "dev/alias", Body: "stale"}},
		{{Name: "dev/null", Type: tar.TypeChar, Major: 1},
			{Name: "dev/alias", Link: "dev/null", Type: tar.TypeLink}},
	}})
	dest := unpackFresh(t, s, d)
	if _, err := os.Lstat(filepath.Join(dest, "dev/alias")); !os.IsNotExist(err) {
		b, _ := os.ReadFile(filepath.Join(dest, "dev/alias"))
		t.Fatalf("dev/alias survived as %q (%v); the image replaced it with a device", b, err)
	}
}

func TestUnpackFreshFixtures(t *testing.T) {
	for _, c := range []struct {
		name   string
		layers [][]tarEntry
		file   string
		want   string
		suffix string
	}{
		{name: "symlink under a symlinked parent resolves", layers: [][]tarEntry{
			{{Name: "usr/"}, {Name: "usr/lib/"}, {Name: "usr/lib/foo", Body: "foo"},
				{Name: "lib", Link: "usr/lib"}, {Name: "lib/bar", Link: "/usr/lib/foo"}},
		}, file: "usr/lib/bar", want: "foo"},
		{name: "dotdot after a symlinked parent resolves", layers: [][]tarEntry{
			{{Name: "usr/"}, {Name: "usr/lib/"}, {Name: "usr/lib/foo", Body: "foo"},
				{Name: "lib", Link: "usr/lib"}, {Name: "link", Link: "/lib/../../usr/lib/foo"}},
		}, file: "link", want: "foo"},
		{name: "trailing separator", layers: [][]tarEntry{{{Name: "f", Body: "x"}}},
			file: "f", want: "x", suffix: string(filepath.Separator)},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, d := storeWithImage(t, "fix:1", testImage{layers: c.layers})
			dest := filepath.Join(t.TempDir(), "rootfs") + c.suffix
			if err := unpackFreshTo(t, s, d, dest, false); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(dest, c.file))
			if err != nil || string(b) != c.want {
				t.Fatalf("%s = %q, %v; want %q", c.file, b, err, c.want)
			}
		})
	}
}

func TestUnpackHardlinkSharesInode(t *testing.T) {
	s, d := storeWithImage(t, "hl:1", testImage{layers: [][]tarEntry{
		{{Name: "orig", Body: "x"}, {Name: "alias", Link: "orig", Type: tar.TypeLink}},
	}})
	dest := unpackFresh(t, s, d)
	a, err := os.Stat(filepath.Join(dest, "orig"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(filepath.Join(dest, "alias"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(a, b) {
		t.Fatal("hardlink must share the inode")
	}
}

func TestUnpackFreshCleansUpStaging(t *testing.T) {
	for _, c := range []struct {
		name        string
		plant       func(t *testing.T, s *store, digest, dest string)
		wantEntries int
	}{
		{name: "corrupt layer", wantEntries: 0, plant: func(t *testing.T, s *store, digest, dest string) {
			m := manifestOf(t, s, digest)
			blob := filepath.Join(s.root, "blobs", "sha256", m.Layers[0].Digest.Hex())
			if err := os.Chmod(blob, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(blob, []byte("not gzip"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "regular file at dest", wantEntries: 1, plant: func(t *testing.T, s *store, digest, dest string) {
			if err := os.WriteFile(dest, nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "dangling symlink at dest", wantEntries: 1, plant: func(t *testing.T, s *store, digest, dest string) {
			if err := os.Symlink(filepath.Join(t.TempDir(), "gone"), dest); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, d := storeWithImage(t, "bad:1", testImage{})
			parent := t.TempDir()
			dest := filepath.Join(parent, "rootfs")
			c.plant(t, s, d, dest)
			if err := unpackFreshTo(t, s, d, dest, false); err == nil {
				t.Fatal("unpack must fail")
			}
			entries, readErr := os.ReadDir(parent)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != c.wantEntries {
				t.Fatalf("parent holds %v, want %d entries", entries, c.wantEntries)
			}
		})
	}
}

func TestUnpackFreshLostRenameRace(t *testing.T) {
	for _, c := range []struct {
		name    string
		inStore bool
		wantErr bool
	}{
		{name: "managed cache reuses the winner", inStore: true, wantErr: false},
		{name: "named rootfs reports the failure", inStore: false, wantErr: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, d := storeWithImage(t, "race:1", testImage{layers: [][]tarEntry{
				{{Name: "f", Body: "x"}},
			}})
			dest := filepath.Join(t.TempDir(), "rootfs")
			if c.inStore {
				var err error
				if dest, err = s.cacheDir(cacheRootfs, d); err != nil {
					t.Fatal(err)
				}
			}
			// An existing directory makes the rename fail the way a peer that
			// published first would.
			if err := os.MkdirAll(filepath.Join(dest, "occupied"), 0o755); err != nil {
				t.Fatal(err)
			}
			parent := filepath.Dir(dest)
			if err := unpackFreshTo(t, s, d, dest, c.inStore); (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, c.wantErr)
			}
			entries, readErr := os.ReadDir(parent)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 1 {
				t.Fatalf("staging leftovers: %v", entries)
			}
		})
	}
}

func TestCmdUnpackStoreCacheAndAlreadyUnpacked(t *testing.T) {
	s, d := storeWithImage(t, "cache:1", testImage{layers: [][]tarEntry{
		{{Name: "etc/"}, {Name: "etc/os-release", Body: "ID=fixture"}},
	}})
	stderr, err := runCaptured(t, "unpack", "--store", s.root, "--rootfs", "", "cache:1")
	if err != nil {
		t.Fatal(err)
	}
	dest, err := s.cacheDir(cacheRootfs, d)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, stderr, "Unpacking cache:1 -> "+dest, "Unpacked cache:1")
	b, err := os.ReadFile(filepath.Join(dest, "etc/os-release"))
	if err != nil || string(b) != "ID=fixture" {
		t.Fatalf("cache content = %q, %v", b, err)
	}

	stderr, err = runCaptured(t, "unpack", "--store", s.root, "cache:1")
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, stderr, "Already unpacked")
}

func TestUnpackCachePrivateModeAndTempSweep(t *testing.T) {
	s, _ := storeWithImage(t, "modes:1", testImage{layers: [][]tarEntry{{{Name: "f", Body: "x"}}}})
	base := s.cacheBase(cacheRootfs)
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(base, ".deadbeef.tmp-1")
	fresh := filepath.Join(base, ".deadbeef.tmp-2")
	for _, d := range []string{stale, fresh} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * staleRootfsTempAge)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := runCaptured(t, "unpack", "--store", s.root, "modes:1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Errorf("abandoned staging tree survived: %v", err)
	}
	if _, err := os.Lstat(fresh); err != nil {
		t.Errorf("a recent staging tree must be left alone: %v", err)
	}
	for _, dir := range []string{filepath.Join(s.root, cacheRootfs), base} {
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode = %o, want 700", dir, fi.Mode().Perm())
		}
	}
}

func TestCmdUnpackExplicitRootfsMerges(t *testing.T) {
	s, _ := storeWithImage(t, "merge:1", testImage{layers: [][]tarEntry{
		{{Name: "fromimage", Body: "i"}},
	}})
	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "user-file"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runCaptured(t, "unpack", "--store", s.root, "--rootfs", dest, "merge:1"); err != nil {
		t.Fatal(err)
	}
	for f, want := range map[string]string{"user-file": "mine", "fromimage": "i"} {
		b, err := os.ReadFile(filepath.Join(dest, f))
		if err != nil || string(b) != want {
			t.Fatalf("%s = %q, %v", f, b, err)
		}
	}
}

func TestCmdUnpackExplicitRootfsFollowsSymlink(t *testing.T) {
	s, _ := storeWithImage(t, "link:1", testImage{layers: [][]tarEntry{
		{{Name: "fromimage", Body: "i"}},
	}})
	real := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := runCaptured(t, "unpack", "--store", s.root, "--rootfs", link, "link:1"); err != nil {
		t.Fatalf("unpack into a symlinked directory = %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(real, "fromimage")); err != nil || string(b) != "i" {
		t.Fatalf("fromimage = %q, %v", b, err)
	}
}

func TestUnpackImageRefusesNonDirectory(t *testing.T) {
	s, _ := storeWithImage(t, "demo:1", testImage{})
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, m, err := s.loadRef(context.Background(), "demo:1", defaultPlatform)
	if err != nil {
		t.Fatal(err)
	}
	err = unpackImage(context.Background(), s, "demo:1", m, file)
	if err == nil || !strings.Contains(err.Error(), "want a directory") {
		t.Fatalf("unpack into a regular file = %v, want a not-a-directory refusal", err)
	}
	if b, readErr := os.ReadFile(file); readErr != nil || string(b) != "x" {
		t.Fatalf("planted file = %q, %v; refusal must not touch it", b, readErr)
	}
}

func TestUnpackMergeResolvesPreexistingSymlinkedParent(t *testing.T) {
	s, _ := storeWithImage(t, "usrmerge:2", testImage{layers: [][]tarEntry{
		{{Name: "usr/"}, {Name: "usr/lib/"}, {Name: "usr/lib/foo", Body: "foo"},
			{Name: "lib64", Link: "lib"}, {Name: "lib64/x", Link: "/usr/lib/foo"}},
	}})
	dest := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dest, "usr", "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/lib", filepath.Join(dest, "lib")); err != nil {
		t.Fatal(err)
	}
	if _, err := runCaptured(t, "unpack", "--store", s.root, "--rootfs", dest, "usrmerge:2"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dest, "usr", "lib", "x"))
	if err != nil || string(b) != "foo" {
		t.Fatalf("usr/lib/x = %q, %v; want it to resolve to foo", b, err)
	}
}

func TestUnpackAppliesFilteredHeaders(t *testing.T) {
	s, d := storeWithImage(t, "filt:1", testImage{layers: [][]tarEntry{
		{{Name: "dev/"}, {Name: "dev/null", Type: tar.TypeChar, Major: 1},
			{Name: "dev/alias", Link: "dev/null", Type: tar.TypeLink},
			{Name: "bin/"}, {Name: "bin/busybox", Body: "x", Mode: 0o2755},
			{Name: "bin/sh", Link: "/bin/busybox"}},
	}})
	dest := unpackFresh(t, s, d)
	for _, absent := range []string{"dev/null", "dev/alias"} {
		if _, err := os.Lstat(filepath.Join(dest, absent)); err == nil {
			t.Errorf("%s: must not be extracted", absent)
		}
	}
	if target, err := os.Readlink(filepath.Join(dest, "bin/sh")); err != nil || target != "../bin/busybox" {
		t.Errorf("bin/sh -> %q, %v; want ../bin/busybox", target, err)
	}
	fi, err := os.Stat(filepath.Join(dest, "bin/busybox"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetgid != 0 {
		t.Errorf("bin/busybox mode %v keeps setgid", fi.Mode())
	}
}

func TestCmdUnpackDoesNotCreateStore(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "typo")
	if _, err := runCaptured(t, "unpack", "--store", missing, "demo:1"); err == nil {
		t.Fatal("a missing store must fail")
	}
	if _, statErr := os.Lstat(missing); !os.IsNotExist(statErr) {
		t.Error("unpack must not create the store directory")
	}
}

func TestUnpackIntoStopsOnCancelledContext(t *testing.T) {
	s, d := storeWithImage(t, "cancel:1", testImage{layers: [][]tarEntry{{{Name: "f", Body: "x"}}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dest := t.TempDir()
	err := unpackInto(ctx, s, manifestOf(t, s, d), dest)
	if err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// With unpigz on PATH, the child's exit status must not replace
// context.Canceled.
func TestUnpackIntoCancelsMidLayer(t *testing.T) {
	s, d := storeWithImage(t, "cancelmid:1", testImage{layers: [][]tarEntry{bigEntries(400, 32*1024)}})
	for _, shim := range []bool{false, true} {
		t.Run(fmt.Sprintf("unpigz=%v", shim), func(t *testing.T) {
			if shim {
				prependPath(t, filepath.Dir(writeShellStub(t, "unpigz", "exec gunzip \"$@\"\n")))
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dest := t.TempDir()
			stop := make(chan struct{})
			defer close(stop)
			go func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					if _, err := os.Lstat(filepath.Join(dest, "f0000")); err == nil {
						cancel()
						return
					}
					time.Sleep(time.Millisecond)
				}
			}()
			err := unpackInto(ctx, s, manifestOf(t, s, d), dest)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
		})
	}
}

func TestUnpackLayerPathTransitions(t *testing.T) {
	for _, c := range []struct {
		name   string
		layers [][]tarEntry
		files  map[string]string
		links  []string
		absent []string
	}{
		{name: "read-only directory", layers: [][]tarEntry{
			{{Name: "ro/", Mode: 0o555}, {Name: "ro/f", Body: "first"}},
			{{Name: "ro/second", Body: "second"}},
		}, files: map[string]string{"ro/f": "first", "ro/second": "second"}},
		{name: "replace symlinked parent", layers: [][]tarEntry{
			{{Name: "usr/lib/"}, {Name: "usr/lib/foo", Body: "foo"}, {Name: "lib", Link: "usr/lib"}},
			{{Name: "lib/"}, {Name: "lib/bar", Link: "/usr/lib/foo"}},
		}, files: map[string]string{"lib/bar": "foo"}},
		{name: "hardlink to symlink to dropped node", layers: [][]tarEntry{
			{{Name: "node", Type: tar.TypeFifo}, {Name: "link", Link: "node"},
				{Name: "alias", Type: tar.TypeLink, Link: "link"}},
		}, links: []string{"link", "alias"}, absent: []string{"node"}},
		{name: "replace symlink with dropped node", layers: [][]tarEntry{
			{{Name: "target", Body: "kept"}, {Name: "node", Link: "target"}},
			{{Name: "node", Type: tar.TypeFifo}, {Name: "alias", Type: tar.TypeLink, Link: "node"}},
		}, files: map[string]string{"target": "kept"}, absent: []string{"node", "alias"}},
		{name: "replace dropped node through parent alias", layers: [][]tarEntry{
			{{Name: "dev/"}, {Name: "alias", Link: "dev"}, {Name: "dev/null", Type: tar.TypeFifo}},
			{{Name: "alias/null", Body: "restored"}, {Name: "copy", Type: tar.TypeLink, Link: "dev/null"}},
		}, files: map[string]string{"copy": "restored"}},
		{name: "absolute target parent traversal", layers: [][]tarEntry{
			{{Name: "a/b/"}, {Name: "l", Link: "a/b"}, {Name: "target", Body: "wrong"},
				{Name: "a/target", Body: "right"}, {Name: "link", Link: "/l/../target"}},
		}, files: map[string]string{"link": "right"}},
		{name: "hardlinked absolute symlink aliases", layers: [][]tarEntry{
			{{Name: "target", Body: "right"}, {Name: "link", Link: "/target"},
				{Name: "dir/alias", Type: tar.TypeLink, Link: "link"}},
			{{Name: "deep/dir/alias", Type: tar.TypeLink, Link: "dir/alias"}},
		}, files: map[string]string{"link": "right", "dir/alias": "right", "deep/dir/alias": "right"}},
		{name: "file replaces a directory case alias", layers: [][]tarEntry{
			{{Name: "A/"}, {Name: "A/sub/"}},
			{{Name: "a", Body: "x"}},
		}, files: map[string]string{"a": "x"}},
		{name: "parent symlink above the root clamps", layers: [][]tarEntry{
			{{Name: "top", Link: "../.."}, {Name: "top/f", Body: "x"},
				{Name: "a/"}, {Name: "a/up", Link: "../../../out"}, {Name: "a/up/g", Body: "y"}},
		}, files: map[string]string{"f": "x", "out/g": "y"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, d := storeWithImage(t, "paths:1", testImage{layers: c.layers})
			dest := unpackFresh(t, s, d)
			for name, want := range c.files {
				got, err := os.ReadFile(filepath.Join(dest, name))
				if err != nil || string(got) != want {
					t.Errorf("%s = %q, %v; want %q", name, got, err, want)
				}
			}
			for _, name := range c.links {
				if fi, err := os.Lstat(filepath.Join(dest, name)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
					t.Errorf("%s = %v, %v; want symlink", name, fi, err)
				}
			}
			for _, name := range c.absent {
				if _, err := os.Lstat(filepath.Join(dest, name)); !os.IsNotExist(err) {
					t.Errorf("%s survived: %v", name, err)
				}
			}
			if c.name == "read-only directory" {
				fi, err := os.Stat(filepath.Join(dest, "ro"))
				if err != nil || fi.Mode().Perm() != 0o555 {
					t.Errorf("ro = %v, %v; want mode 0555", fi, err)
				}
			}
		})
	}
}

func TestUnpackRestoresDirectoryModesAfterFailure(t *testing.T) {
	s, digest := storeWithImage(t, "modes:1", testImage{layers: [][]tarEntry{{
		{Name: "ro/new", Body: "new"},
		{Name: "closed/", Mode: 0o4000},
		{Name: "closed/file", Body: "file"},
		{Name: "bad", Type: tar.TypeLink, Link: "missing"},
	}}})
	dest := t.TempDir()
	t.Cleanup(func() { _ = removeRootfsTree(dest) })
	ro := filepath.Join(dest, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	err := unpackInto(context.Background(), s, manifestOf(t, s, digest), dest)
	if err == nil {
		t.Fatal("missing hardlink target must fail")
	}
	for name, mode := range map[string]os.FileMode{"ro": 0o500, "closed": 0} {
		fi, err := os.Stat(filepath.Join(dest, name))
		if err != nil || fi.Mode().Perm() != mode {
			t.Errorf("%s: %v, %v; want mode %o", name, fi, err, mode)
		}
	}
	if got, err := os.ReadFile(filepath.Join(ro, "new")); err != nil || string(got) != "new" {
		t.Fatalf("read-only parent: %q, %v", got, err)
	}
}

func TestRemoveRootfsTreePreservesSymlinkTargets(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "kept"), []byte("kept"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "closed"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "closed", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "closed"), 0); err != nil {
		t.Fatal(err)
	}
	if err := removeRootfsTree(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("root survived: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(outside, "kept")); err != nil || string(got) != "kept" {
		t.Fatalf("symlink target: %q, %v", got, err)
	}
}

func TestUnpackOpaqueKeepsCurrentLayerPolicy(t *testing.T) {
	s, d := storeWithImage(t, "opaque:1", testImage{layers: [][]tarEntry{
		{{Name: "target", Body: "right"}, {Name: "d/"}, {Name: "d/old", Body: "old"}},
		{{Name: "d/", Mode: 0o555}, {Name: "d/link", Link: "/target"},
			{Name: "d/node", Type: tar.TypeFifo}, {Name: "d/.wh..wh..opq"},
			{Name: "d/sub/alias", Type: tar.TypeLink, Link: "d/link"},
			{Name: "d/dropped", Type: tar.TypeLink, Link: "d/node"}},
	}})
	dest := unpackFresh(t, s, d)
	if got, err := os.ReadFile(filepath.Join(dest, "d/sub/alias")); err != nil || string(got) != "right" {
		t.Fatalf("hardlinked symlink: %q, %v", got, err)
	}
	for _, name := range []string{"d/old", "d/node", "d/dropped"} {
		if _, err := os.Lstat(filepath.Join(dest, name)); !os.IsNotExist(err) {
			t.Errorf("%s survived: %v", name, err)
		}
	}
}

func TestUnpackRefusesEscapingPaths(t *testing.T) {
	for _, entries := range [][]tarEntry{
		{{Name: "../outside", Body: "bad"}},
		{{Name: "hardlink", Type: tar.TypeLink, Link: "../outside"}},
		{{Name: "cycle", Link: "cycle"}, {Name: "cycle/file", Body: "bad"}},
	} {
		s, d := storeWithImage(t, "escape:1", testImage{layers: [][]tarEntry{entries}})
		dest := filepath.Join(t.TempDir(), "rootfs")
		if err := unpackFreshTo(t, s, d, dest, false); err == nil {
			t.Errorf("accepted %v", entries)
		}
		if _, err := os.Lstat(dest); !os.IsNotExist(err) {
			t.Errorf("published failed tree: %v", err)
		}
	}
}

func TestUnpackRefusesStoreCaseAliases(t *testing.T) {
	s, err := openStore(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ensureLayout(context.Background()); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(filepath.Dir(s.root), "STORE")
	original, err := os.Stat(s.root)
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.Stat(alias)
	if os.IsNotExist(err) {
		t.Skip("requires a case-insensitive filesystem")
	}
	if err != nil || !os.SameFile(original, other) {
		t.Fatalf("case alias: %v", err)
	}
	digest := pushTestImage(t, s, testImage{layers: [][]tarEntry{{{Name: ".wh.index.json"}}}})
	pinImage(t, s, "demo:1", defaultPlatform, digest)
	before, err := os.ReadFile(filepath.Join(s.root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dest := range []string{alias, filepath.Join(alias, "missing", "child")} {
		if _, err := runCaptured(t, "unpack", "--store", s.root, "--rootfs", dest, "demo:1"); err == nil || !strings.Contains(err.Error(), "inside the store") {
			t.Errorf("rootfs %s: %v", dest, err)
		}
	}
	after, err := os.ReadFile(filepath.Join(s.root, "index.json"))
	if err != nil || string(before) != string(after) {
		t.Fatalf("store index changed: %v", err)
	}
}
