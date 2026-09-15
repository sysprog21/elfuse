// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/go-archive"
	"github.com/moby/go-archive/compression"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// staleRootfsTempAge bounds how long an abandoned staging tree survives.
// Unpacks run without the store lock, so a shorter window could delete the
// tree a concurrent unpack is still filling.
const staleRootfsTempAge = 24 * time.Hour

type unpackCommand struct {
	commonFlags
	Rootfs string `help:"Unpack into this directory instead of the managed cache" type:"path"`
	Ref    string `arg:"" name:"ref" help:"Stored image reference"`
}

func (c *unpackCommand) Run() error {
	s, platform, err := c.commonFlags.openStoreForRead()
	if err != nil {
		return err
	}
	if err := refuseRootfsInStore(s.root, c.Rootfs); err != nil {
		return err
	}
	ctx := context.Background()
	digest, manifest, err := s.loadRef(ctx, c.Ref, platform)
	if err != nil {
		return err
	}
	if c.Rootfs != "" {
		err = unpackImage(ctx, s, c.Ref, manifest, c.Rootfs)
	} else {
		var dest string
		if dest, err = s.cacheDir(cacheRootfs, digest); err == nil {
			err = ensureRootfs(ctx, s, c.Ref, manifest, dest)
		}
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Unpacked %s\n", c.Ref)
	return nil
}

func ensureRootfs(ctx context.Context, s *store, ref string, manifest ocispec.Manifest, dest string) error {
	published, err := existingDirectory(dest)
	if err != nil {
		return err
	}
	if published {
		fmt.Fprintf(os.Stderr, "Already unpacked %s -> %s\n", ref, dest)
		return nil
	}
	fmt.Fprintf(os.Stderr, "Unpacking %s -> %s\n", ref, dest)
	return unpackImageFresh(ctx, s, manifest, dest)
}

func unpackImage(ctx context.Context, s *store, ref string, manifest ocispec.Manifest, dest string) error {
	// dest may be a symlink to the directory; classify its target.
	dest = resolvedAbs(dest)
	fmt.Fprintf(os.Stderr, "Unpacking %s -> %s\n", ref, dest)
	exists, err := existingDirectory(dest)
	if err != nil {
		return err
	}
	if exists {
		return unpackInto(ctx, s, manifest, dest)
	}
	return unpackImageFresh(ctx, s, manifest, dest)
}

func existingDirectory(path string) (bool, error) {
	kind, err := classifyPath(path, false)
	if err != nil {
		return false, err
	}
	switch kind {
	case fileAbsent:
		return false, nil
	case fileDirectory:
		return true, nil
	}
	return false, fmt.Errorf("%s is a %s, want a directory", path, kind)
}

func unpackImageFresh(ctx context.Context, s *store, manifest ocispec.Manifest, dest string) (err error) {
	dest = filepath.Clean(dest)
	parent := filepath.Dir(dest)
	// A managed cache entry lives inside the store and takes the store's
	// private mode; a directory the caller named does not.
	cached := insideStore(s.root, dest)
	mode := os.FileMode(0o755)
	if cached {
		mode = 0o700
		if err := ensurePrivateDir(parent); err != nil {
			return err
		}
		if err := os.Chmod(filepath.Dir(parent), 0o700); err != nil {
			return err
		}
		if err := sweepStaleRootfsTemps(parent); err != nil {
			return err
		}
	} else if err := os.MkdirAll(parent, mode); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, rootfsTempPrefix(filepath.Base(dest)))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, removeRootfsTree(tmp)) }()
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	if err := unpackInto(ctx, s, manifest, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		// Only a content-addressed cache entry can lose this race benignly,
		// because any completed tree there holds the same image.
		if cached {
			if published, pubErr := existingDirectory(dest); published && pubErr == nil {
				return nil
			}
		}
		return err
	}
	return syncDirectory(parent)
}

func rootfsTempPrefix(base string) string {
	return "." + base + ".tmp-"
}

func isRootfsTemp(name string) bool {
	return strings.HasPrefix(name, ".") && strings.Contains(name, ".tmp-")
}

// sweepStaleRootfsTemps removes staging trees left behind by an unpack that was
// killed before its deferred cleanup could run.
func sweepStaleRootfsTemps(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !isRootfsTemp(entry.Name()) {
			continue
		}
		fi, err := entry.Info()
		if err != nil || time.Since(fi.ModTime()) < staleRootfsTempAge {
			continue
		}
		if err := removeRootfsTree(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func unpackInto(ctx context.Context, s *store, manifest ocispec.Manifest, dest string) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	policy, err := newLayerPolicy(dest)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, policy.Close()) }()
	for i, layer := range manifest.Layers {
		if err := applyStoredLayer(ctx, s, dest, policy, layer); err != nil {
			return fmt.Errorf("unpack: layer %d (%s): %w", i, layer.Digest, err)
		}
	}
	return nil
}

func applyStoredLayer(ctx context.Context, s *store, dest string, policy *layerPolicy, layer ocispec.Descriptor) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	hash, err := v1.NewHash(layer.Digest.String())
	if err != nil {
		return err
	}
	blob, err := s.blob(hash)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, blob.Close()) }()
	if err := applyLayer(dest, contextReader{ctx: ctx, r: blob}, policy); err != nil {
		// go-archive may decompress through an unpigz child, whose exit
		// status is what a cancelled read surfaces as.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
}

func unpackOptions() *archive.TarOptions {
	return &archive.TarOptions{NoLchown: true, BestEffortXattrs: true}
}

func applyLayer(dest string, blob io.Reader, policy *layerPolicy) (err error) {
	decompressed, err := compression.DecompressStream(blob)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, decompressed.Close()) }()
	_, err = archive.ApplyUncompressedLayer(dest, filterLayer(decompressed, policy), unpackOptions())
	return err
}

// walkRootfsDirs visits directories before their children and never follows
// symlinks, so permissions can be relaxed before reading a directory.
func walkRootfsDirs(root *os.Root, name string, visit func(string, os.FileInfo) error) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}
	if err := visit(name, info); err != nil {
		return err
	}
	dir, err := root.Open(name)
	if err != nil {
		return err
	}
	names, err := dir.Readdirnames(-1)
	if closeErr := dir.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	for _, child := range names {
		if err := walkRootfsDirs(root, filepath.Join(name, child), visit); err != nil {
			return err
		}
	}
	return nil
}

func removeRootfsTree(name string) error {
	// Open the parent so a symlink at name is removed as a link.
	parent, err := os.OpenRoot(filepath.Dir(name))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	base := filepath.Base(name)
	err = walkRootfsDirs(parent, base, func(rel string, info os.FileInfo) error {
		return parent.Chmod(rel, info.Mode().Perm()|0o700)
	})
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return parent.RemoveAll(base)
}
