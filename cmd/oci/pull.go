// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type pullCommand struct {
	commonFlags
	Timeout time.Duration `help:"Fail the pull after this duration; zero disables the limit" default:"0"`
	Ref     string        `arg:"" name:"ref" help:"Image reference"`
}

func (c *pullCommand) Run() error {
	if c.Timeout < 0 {
		return fmt.Errorf("pull: --timeout %s is negative", c.Timeout)
	}
	s, platform, err := c.commonFlags.openStore()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	return pullImage(ctx, s, c.Ref, platform)
}

func normalizeRef(ref string) (name.Reference, error) {
	return name.ParseReference(ref, name.WeakValidation)
}

func imagePlatform(ctx context.Context, s *store, img v1.Image) (v1.Platform, error) {
	manifest, err := img.Manifest()
	if err != nil {
		return v1.Platform{}, err
	}
	raw, err := s.verifiedBlobBytes(ctx, manifest.Config)
	if os.IsNotExist(err) {
		raw, err = img.RawConfigFile()
	}
	if err != nil {
		return v1.Platform{}, err
	}
	config, err := v1.ParseConfigFile(bytes.NewReader(raw))
	if err != nil {
		return v1.Platform{}, err
	}
	return v1.Platform{
		OS:           config.OS,
		Architecture: config.Architecture,
		Variant:      config.Variant,
	}, nil
}

func indexChildImage(ctx context.Context, s *store, index v1.ImageIndex, child v1.Descriptor) (v1.Image, v1.Platform, error) {
	if !child.MediaType.IsImage() {
		return nil, v1.Platform{}, fmt.Errorf("unexpected index child media type %s", child.MediaType)
	}
	img, err := index.Image(child.Digest)
	if err != nil {
		return nil, v1.Platform{}, err
	}
	actual, err := imagePlatform(ctx, s, img)
	return img, actual, err
}

func normalizeImagePlatform(platform v1.Platform) v1.Platform {
	if platform.Architecture == "arm64" && platform.Variant == "v8" {
		platform.Variant = ""
	}
	return platform
}

func imagePlatformMatches(actual, requested v1.Platform) bool {
	actual = normalizeImagePlatform(actual)
	requested = normalizeImagePlatform(requested)
	return actual.OS == requested.OS &&
		actual.Architecture == requested.Architecture &&
		actual.Variant == requested.Variant
}

func selectIndexImage(ctx context.Context, s *store, index v1.ImageIndex, platform v1.Platform) (v1.Image, error) {
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, err
	}
	for _, child := range manifest.Manifests {
		if child.Platform == nil || !imagePlatformMatches(*child.Platform, platform) {
			continue
		}
		img, actual, err := indexChildImage(ctx, s, index, child)
		if err != nil {
			return nil, err
		}
		if !imagePlatformMatches(actual, platform) {
			return nil, fmt.Errorf("image platform is %s, not %s", actual, platform)
		}
		return img, nil
	}
	for _, child := range manifest.Manifests {
		if child.Platform != nil {
			continue
		}
		img, actual, err := indexChildImage(ctx, s, index, child)
		if err != nil {
			return nil, err
		}
		if imagePlatformMatches(actual, platform) {
			return img, nil
		}
	}
	return nil, fmt.Errorf("no image for platform %s", platform)
}

func selectImage(ctx context.Context, s *store, desc *remote.Descriptor, platform v1.Platform) (v1.Image, error) {
	if desc.MediaType.IsIndex() {
		index, err := desc.ImageIndex()
		if err != nil {
			return nil, err
		}
		return selectIndexImage(ctx, s, index, platform)
	}
	if !desc.MediaType.IsImage() {
		return nil, fmt.Errorf("unexpected media type %s", desc.MediaType)
	}
	img, err := desc.Image()
	if err != nil {
		return nil, err
	}
	actual, err := imagePlatform(ctx, s, img)
	if err != nil {
		return nil, err
	}
	if !imagePlatformMatches(actual, platform) {
		return nil, fmt.Errorf("image platform is %s, not %s", actual, platform)
	}
	return img, nil
}

type imageFetcher func(context.Context, name.Reference, v1.Platform) (v1.Image, error)

func fetchRemoteImage(ctx context.Context, s *store, ref name.Reference, platform v1.Platform) (v1.Image, error) {
	desc, err := remote.Get(ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithPlatform(platform),
	)
	if err != nil {
		return nil, err
	}
	return selectImage(ctx, s, desc, platform)
}

func pullImage(ctx context.Context, s *store, ref string, platform ocispec.Platform) error {
	return pullImageWithFetcher(ctx, s, ref, platform, func(ctx context.Context, ref name.Reference, platform v1.Platform) (v1.Image, error) {
		return fetchRemoteImage(ctx, s, ref, platform)
	})
}

func pullImageWithFetcher(ctx context.Context, s *store, ref string, platform ocispec.Platform, fetch imageFetcher) error {
	parsed, err := normalizeRef(ref)
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	fmt.Fprintf(os.Stderr, "Pulling %s...\n", parsed.Name())
	if err := s.ensureLayout(ctx); err != nil {
		return err
	}
	p := v1.Platform{OS: platform.OS, Architecture: platform.Architecture, Variant: platform.Variant}
	img, err := fetch(ctx, parsed, p)
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	manifest, err := s.publishImage(ctx, img, platform)
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	if err := s.withLock(ctx, func() error {
		if err := s.pinLocked(ctx, parsed.Name(), platform, manifest); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	fmt.Fprintf(os.Stderr, "Pulled %s -> %s\n", parsed.Name(), manifest.Digest)
	return nil
}
