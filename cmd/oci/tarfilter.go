// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"

	"github.com/moby/go-archive"
)

const tarSpecialBits = 0o4000 | 0o2000 | 0o1000
const filterCopyBufferSize = 32 * 1024

type layerRecord struct {
	kind   byte
	mode   os.FileMode
	target string
	layer  int
}

type layerPolicy struct {
	root       *os.Root
	records    map[string]layerRecord
	layer      int
	warnedNode bool
	warnedBits bool
}

func newLayerPolicy(dest string) (*layerPolicy, error) {
	root, err := os.OpenRoot(dest)
	if err != nil {
		return nil, err
	}
	p := &layerPolicy{root: root, records: make(map[string]layerRecord)}
	err = walkRootfsDirs(root, ".", func(name string, info os.FileInfo) error {
		p.records[name] = layerRecord{kind: tar.TypeDir, mode: info.Mode()}
		return root.Chmod(name, info.Mode()|0o700)
	})
	if err != nil {
		return nil, errors.Join(err, p.Close())
	}
	return p, nil
}

func (p *layerPolicy) Close() error {
	var dirs []string
	for name, record := range p.records {
		if record.kind == tar.TypeDir {
			dirs = append(dirs, name)
		}
	}
	// Descendants must remain reachable until their modes are restored.
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	var result error
	for _, name := range dirs {
		info, err := p.root.Lstat(name)
		if os.IsNotExist(err) {
			continue
		}
		if err == nil && info.IsDir() {
			err = p.root.Chmod(name, p.records[name].mode)
		}
		result = errors.Join(result, err)
	}
	return errors.Join(result, p.root.Close())
}

func (p *layerPolicy) filter(hdr *tar.Header) error {
	name, err := p.entryPath(hdr.Name)
	if err != nil {
		return err
	}
	if name == "." {
		return nil // go-archive ignores headers for the extraction root.
	}
	if hdr.Name != name && (hdr.Typeflag != tar.TypeDir || hdr.Name != name+"/") {
		hdr.Name = name
		hdr.Format = tar.FormatPAX
	}
	base := path.Base(name)
	if base == archive.WhiteoutOpaqueDir {
		p.forget(path.Dir(name), true)
		return nil
	}
	if strings.HasPrefix(base, archive.WhiteoutPrefix) {
		p.forget(path.Join(path.Dir(name), strings.TrimPrefix(base, archive.WhiteoutPrefix)), false)
		return nil
	}

	record := layerRecord{kind: hdr.Typeflag}
	if hdr.Typeflag == tar.TypeLink {
		target, err := p.entryPath(hdr.Linkname)
		if err != nil {
			return err
		}
		record = p.records[target]
		if record.target == "" {
			if info, err := p.root.Lstat(target); err == nil && info.Mode()&os.ModeSymlink != 0 {
				link, err := p.root.Readlink(target)
				if err != nil {
					return err
				}
				if path.IsAbs(link) {
					record = layerRecord{kind: tar.TypeSymlink, target: link}
				}
			}
		}
		if hdr.Linkname != target {
			hdr.Linkname = target
			hdr.Format = tar.FormatPAX
		}
		if record.kind == tar.TypeSymlink && record.target != "" {
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = record.target
			hdr.Format = tar.FormatPAX
		}
	}
	if hdr.Typeflag == tar.TypeDir {
		delete(p.records, name)
	} else {
		p.forget(name, false)
	}
	switch record.kind {
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		p.records[name] = layerRecord{kind: record.kind, layer: p.layer}
		if !p.warnedNode {
			p.warnedNode = true
			fmt.Fprintf(os.Stderr, "elfuse-oci: unpack: dropping device and FIFO entries (first: %q)\n", hdr.Name)
		}
		hdr.Name = path.Join(path.Dir(name), archive.WhiteoutPrefix+base)
		hdr.Typeflag, hdr.Linkname, hdr.Size = tar.TypeReg, "", 0
		hdr.Format = tar.FormatPAX
		return nil
	}
	if hdr.Mode&tarSpecialBits != 0 {
		hdr.Mode &^= tarSpecialBits
		if !p.warnedBits {
			p.warnedBits = true
			fmt.Fprintf(os.Stderr, "elfuse-oci: unpack: clearing special permission bits (first: %q)\n", hdr.Name)
		}
	}
	switch hdr.Typeflag {
	case tar.TypeDir:
		p.records[name] = layerRecord{kind: tar.TypeDir, mode: os.FileMode(hdr.Mode).Perm(), layer: p.layer}
		hdr.Mode |= 0o700
	case tar.TypeSymlink:
		if path.IsAbs(hdr.Linkname) {
			p.records[name] = layerRecord{kind: tar.TypeSymlink, target: hdr.Linkname, layer: p.layer}
			hdr.Linkname = relativeTarget(path.Dir(name), hdr.Linkname)
			hdr.Format = tar.FormatPAX
		}
	}
	return nil
}

func (p *layerPolicy) forget(name string, opaque bool) {
	if !opaque {
		info, err := p.root.Lstat(name)
		if os.IsNotExist(err) || err == nil && !info.IsDir() {
			delete(p.records, name)
			return
		}
	}
	prefix := name + "/"
	if name == "." {
		prefix = ""
	}
	for key, record := range p.records {
		if opaque && (key == name || record.layer == p.layer) {
			continue
		}
		if key == name || strings.HasPrefix(key, prefix) {
			delete(p.records, key)
		}
	}
}

// Entry operations replace or link the final component itself.
func (p *layerPolicy) entryPath(name string) (string, error) {
	name = path.Clean(strings.TrimLeft(name, "/"))
	if name == "." {
		return name, nil
	}
	if name == ".." || strings.HasPrefix(name, "../") {
		return "", fmt.Errorf("invalid entry path %q", name)
	}
	dir, err := p.resolveDirectory(path.Dir(name))
	if err != nil {
		return "", err
	}
	return path.Join(dir, path.Base(name)), nil
}

func (p *layerPolicy) resolveDirectory(dir string) (string, error) {
	var resolved []string
	pending := strings.Split(dir, "/")
	links := 0
	for len(pending) != 0 {
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			// A symlink target may climb above the root; clamp there like
			// go-archive and the kernel. Entry names were checked by entryPath.
			if len(resolved) != 0 {
				resolved = resolved[:len(resolved)-1]
			}
			continue
		}
		candidate := path.Join(strings.Join(resolved, "/"), part)
		info, err := p.root.Lstat(candidate)
		if os.IsNotExist(err) || err == nil && info.Mode()&os.ModeSymlink == 0 {
			resolved = append(resolved, part)
			continue
		}
		if err != nil {
			return "", err
		}
		links++
		if links > 40 {
			return "", fmt.Errorf("resolve %q: %w", dir, syscall.ELOOP)
		}
		target, err := p.root.Readlink(candidate)
		if err != nil {
			return "", err
		}
		if path.IsAbs(target) {
			resolved = nil
		}
		pending = append(strings.Split(target, "/"), pending...)
	}
	return path.Join(".", strings.Join(resolved, "/")), nil
}

func relativeTarget(dir, target string) string {
	prefix := ""
	if dir != "." && dir != "" {
		prefix = strings.Repeat("../", strings.Count(dir, "/")+1)
	}
	// Keep target traversal intact: a/../b may cross a symlink at a.
	target = strings.TrimLeft(target, "/")
	if target == "" {
		target = "."
	}
	return prefix + target
}

// go-archive requests the next header only after applying the previous one.
type filteredLayer struct {
	tr      *tar.Reader
	tw      *tar.Writer
	pending bytes.Buffer
	inBody  bool
	err     error
	policy  *layerPolicy
	buf     [filterCopyBufferSize]byte
}

func filterLayer(src io.Reader, policy *layerPolicy) io.Reader {
	policy.layer++
	r := &filteredLayer{tr: tar.NewReader(src), policy: policy}
	r.tw = tar.NewWriter(&r.pending)
	return r
}

func (r *filteredLayer) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	if r.pending.Len() != 0 {
		return r.pending.Read(dst)
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.inBody {
		// The reader bounds the body itself, and yields none for the types
		// whose size field archive/tar ignores.
		n, err := r.tr.Read(r.buf[:])
		if n != 0 {
			_, r.err = r.tw.Write(r.buf[:n])
		}
		if err == io.EOF {
			r.inBody = false
		} else if err != nil {
			r.err = err
		}
	} else {
		hdr, err := r.tr.Next()
		switch {
		case err == io.EOF:
			r.err = r.tw.Close()
			if r.err == nil {
				r.err = io.EOF
			}
		case err != nil:
			r.err = err
		default:
			if r.err = r.policy.filter(hdr); r.err == nil {
				r.err = r.tw.WriteHeader(hdr)
				r.inBody = true
			}
		}
	}
	if r.pending.Len() != 0 {
		return r.pending.Read(dst)
	}
	return 0, r.err
}
