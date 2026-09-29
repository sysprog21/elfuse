// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var version = "dev"

var defaultPlatform = ocispec.Platform{OS: "linux", Architecture: "arm64"}

func parsePlatform(s string) (ocispec.Platform, error) {
	parts := strings.Split(s, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" || len(parts) == 3 && parts[2] == "" {
		return ocispec.Platform{}, fmt.Errorf("invalid --platform %q: expected os/arch[/variant]", s)
	}
	p, err := v1.ParsePlatform(s)
	if err != nil {
		return ocispec.Platform{}, fmt.Errorf("invalid --platform: %w", err)
	}
	if p.OS != "linux" {
		return ocispec.Platform{}, fmt.Errorf("invalid --platform %q: OS must be linux", s)
	}
	switch p.Architecture {
	case "aarch64":
		p.Architecture = "arm64"
	case "x86_64":
		p.Architecture = "amd64"
	}
	if p.Architecture != "arm64" && p.Architecture != "amd64" {
		return ocispec.Platform{}, fmt.Errorf("invalid --platform %q: architecture must be arm64 or amd64", s)
	}
	if p.Architecture == "arm64" && p.Variant == "v8" {
		p.Variant = ""
	}
	if p.Variant != "" {
		return ocispec.Platform{}, fmt.Errorf("invalid --platform %q: variants are not supported", s)
	}
	if p.OSVersion != "" || len(p.OSFeatures) != 0 || len(p.Features) != 0 {
		return ocispec.Platform{}, fmt.Errorf("invalid --platform %q: expected os/arch[/variant]", s)
	}
	return ocispec.Platform{OS: p.OS, Architecture: p.Architecture, Variant: p.Variant}, nil
}

func platformString(p ocispec.Platform) string {
	return v1.Platform{OS: p.OS, Architecture: p.Architecture, Variant: p.Variant}.String()
}

func defaultStore() (string, error) {
	if s := os.Getenv("ELFUSE_OCI_STORE"); s != "" {
		return s, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("no --store given and HOME is unset: %w", err)
	}
	return filepath.Join(home, ".local", "share", "elfuse", "oci"), nil
}

type commonFlags struct {
	Store    string `help:"OCI store directory" env:"ELFUSE_OCI_STORE" type:"path"`
	Platform string `help:"Target platform os/arch[/variant]" default:"linux/arm64"`
}

func (cf *commonFlags) values() (string, ocispec.Platform, error) {
	root := cf.Store
	if root == "" {
		var err error
		root, err = defaultStore()
		if err != nil {
			return "", ocispec.Platform{}, err
		}
	}
	p, err := parsePlatform(cf.Platform)
	if err != nil {
		return "", ocispec.Platform{}, err
	}
	return root, p, nil
}

func (cf *commonFlags) openStore() (*store, ocispec.Platform, error) {
	root, platform, err := cf.values()
	if err != nil {
		return nil, ocispec.Platform{}, err
	}
	s, err := openStore(root)
	return s, platform, err
}

func (cf *commonFlags) openStoreForRead() (*store, ocispec.Platform, error) {
	root, platform, err := cf.values()
	if err != nil {
		return nil, ocispec.Platform{}, err
	}
	s, err := openStoreForRead(root)
	return s, platform, err
}
