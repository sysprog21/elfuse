# elfuse -- aarch64-linux ELF executor on macOS Apple Silicon
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Usage:
#   make <target> [SIGN_IDENTITY="Your Signing Identity"]
#
# Example: make elfuse
#          make test-hello
#          make V=1 elfuse    (verbose -- show full commands)

.DEFAULT_GOAL := help
.DELETE_ON_ERROR:

include mk/toolchain.mk
include mk/config.mk

# Source files.
SRCS := \
    main.c \
    core/guest.c \
    core/elf.c \
    core/stack.c \
    core/vdso.c \
    core/shim-globals.c \
    core/bootstrap.c \
    core/rosetta.c \
    core/launch.c \
    core/sysroot.c \
    runtime/thread.c \
    runtime/futex.c \
    runtime/forkipc.c \
    runtime/fork-state.c \
    runtime/procemu.c \
    runtime/proctitle.c \
    syscall/syscall.c \
    syscall/fdtable.c \
    syscall/translate.c \
    syscall/mem.c \
    syscall/path.c \
    syscall/fuse.c \
    syscall/sidecar.c \
    syscall/chown-overlay.c \
    syscall/fs.c \
    syscall/fs-stat.c \
    syscall/fs-xattr.c \
    syscall/io.c \
    syscall/poll.c \
    syscall/fd.c \
    syscall/inotify.c \
    syscall/time.c \
    syscall/sys.c \
    syscall/proc.c \
    syscall/proc-identity.c \
    syscall/proc-pidfd.c \
    syscall/proc-state.c \
    syscall/exec.c \
    syscall/signal.c \
    syscall/net.c \
    syscall/net-msg.c \
    syscall/net-abi.c \
    syscall/net-absock.c \
    syscall/net-sockopt.c \
    syscall/netlink.c \
    syscall/sysvipc.c \
    debug/crashreport.c \
    debug/gdbstub.c \
    debug/gdbstub-reg.c \
    debug/gdbstub-rsp.c \
    debug/log.c \
    debug/syscall-hist.c \
    oci/ref.c \
    oci/util.c \
    oci/cli.c \
    oci/digest.c \
    oci/digest-set.c \
    oci/blob-store.c \
    oci/media-type.c \
    oci/manifest.c \
    oci/store.c \
    oci/pull.c \
    oci/inspect.c \
    oci/dedup-metrics.c \
    oci/status.c \
    oci/tar.c \
    oci/layer-meta.c \
    oci/layer-apply.c \
    oci/origin-meta.c \
    oci/volume.c \
    oci/volume-list.c \
    oci/clone-rootfs.c \
    oci/unpack.c \
    oci/rebuild-cache.c \
    oci/runspec.c \
    oci/user-lookup.c \
    oci/path-resolve.c \
    oci/runtime-files.c \
    oci/run.c

SRCS := $(addprefix src/,$(SRCS))
OBJS := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# cJSON (JSON parser for OCI manifests / config / policy) is consumed as a
# system shared library via pkg-config, mirroring libarchive / libcurl.
# Install with `brew install cjson` (macOS) or `apt-get install libcjson-dev`
# (Linux). It is used across the OCI subsystem, so the include path goes into
# the global CFLAGS rather than a per-translation-unit override.
CJSON_CFLAGS := $(shell pkg-config --cflags libcjson)
CJSON_LIBS := $(shell pkg-config --libs libcjson)
CFLAGS += $(CJSON_CFLAGS)

# libarchive backs the OCI tar reader (src/oci/tar.c): tar format work
# (ustar / GNU / PAX) plus gzip and zstd layer decoding in one stop. The
# macOS SDK ships only the link stub (libarchive.tbd, no headers), so the
# brew keg provides both; the keg is keg-only, hence the explicit
# PKG_CONFIG_PATH fallback. Install with `brew install libarchive`
# (macOS) or `apt-get install libarchive-dev` (Linux).
LIBARCHIVE_PC := PKG_CONFIG_PATH="$$PKG_CONFIG_PATH:/opt/homebrew/opt/libarchive/lib/pkgconfig:/usr/local/opt/libarchive/lib/pkgconfig" pkg-config
LIBARCHIVE_CFLAGS := $(shell $(LIBARCHIVE_PC) --cflags libarchive)
LIBARCHIVE_LIBS := $(shell $(LIBARCHIVE_PC) --libs libarchive)

DISPATCH_MANIFEST := src/syscall/dispatch.tbl
DISPATCH_GENERATOR := scripts/gen-syscall-dispatch.py
DISPATCH_HEADER := $(BUILD_DIR)/dispatch.h
# $(LIBARCHIVE_LIBS): tar + gzip/zstd decode for OCI layer unpack.
# $(CJSON_LIBS): JSON parsing for OCI manifests/config/policy (system cJSON).
HVF_LDFLAGS := -framework Hypervisor -arch arm64 $(LIBARCHIVE_LIBS) $(CJSON_LIBS)

# Generated headers under build/ that must exist before compiling sources that
# include them.
GENERATED_HEADERS := $(BUILD_DIR)/shim_blob.h $(BUILD_DIR)/version.h $(DISPATCH_HEADER)

include mk/common.mk
include mk/shim.mk

define link-and-sign
	@echo "  LD      $1"
	$(Q)tmp="$1.$$$$.tmp"; \
	$(CC) $(CFLAGS) -o "$$tmp" $2 $(HVF_LDFLAGS); \
	echo "  SIGN    $1"; \
	codesign --entitlements $(ENTITLEMENTS) -f -s "$(SIGN_IDENTITY)" "$$tmp"; \
	mv "$$tmp" "$1"
endef

# Main executable
.PHONY: all elfuse
.PHONY: gen-syscall-dispatch check-syscall-dispatch

all: elfuse

## Regenerate build/dispatch.h from src/syscall/dispatch.tbl
gen-syscall-dispatch:
	@python3 $(DISPATCH_GENERATOR)

## Verify build/dispatch.h matches the generator output
check-syscall-dispatch: $(DISPATCH_HEADER)
	@python3 $(DISPATCH_GENERATOR) --check

$(DISPATCH_HEADER): $(DISPATCH_MANIFEST) $(DISPATCH_GENERATOR) src/syscall/abi.h | $(BUILD_DIR)
	@echo "  GEN     $@"
	$(Q)tmp="$@.$$$$.tmp"; \
	python3 $(DISPATCH_GENERATOR) --output "$$tmp"; \
	cmp -s "$$tmp" "$@" 2>/dev/null || mv "$$tmp" "$@"; \
	rm -f "$$tmp"

$(BUILD_DIR)/syscall/syscall.o: $(DISPATCH_HEADER)

## Build the elfuse executable
elfuse: $(ELFUSE_BIN)

$(ELFUSE_BIN): $(OBJS) | $(BUILD_DIR)
	$(call link-and-sign,$@,$(OBJS))
	@echo "  LN      $(BUILD_DIR)/elfuse-container"
	$(Q)ln -sf elfuse $(BUILD_DIR)/elfuse-container

# Native test binaries (macOS, Hypervisor.framework)

## Build the multi-vCPU HVF validation test (native macOS binary)
$(BUILD_DIR)/test-multi-vcpu: $(BUILD_DIR)/test-multi-vcpu.o | $(BUILD_DIR)
	$(call link-and-sign,$@,$<)

## Build the RWX W^X validation test (native macOS binary)
$(BUILD_DIR)/test-rwx: $(BUILD_DIR)/test-rwx.o | $(BUILD_DIR)
	$(call link-and-sign,$@,$<)

## Build the TLBI RVAE1IS operand encoder unit test (native macOS binary).
# Pure C; no HVF entitlement needed. Verifies the architectural bit-layout
# of tlbi_rvae1is_operand so a future regression that drops TG=01 (which
# the Apple Silicon integration tests would silently tolerate) fails CI
# immediately.
$(BUILD_DIR)/test-tlbi-encoder-host: $(BUILD_DIR)/test-tlbi-encoder-host.o \
		| $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the fork IPC protocol identity unit test (native macOS binary).
# Pure C; no HVF entitlement needed. Pins the first header word as the
# cross-version protocol discriminator after IPC_VERSION removal.
$(BUILD_DIR)/test-fork-ipc-protocol-host: \
		$(BUILD_DIR)/test-fork-ipc-protocol-host.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the identity override host test (native macOS binary)
$(BUILD_DIR)/test-identity-override-host: \
		$(BUILD_DIR)/test-identity-override-host.o \
		$(BUILD_DIR)/syscall/proc-identity.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the proctitle argv-tail regression test (native macOS binary)
# Links against the project-built proctitle.o so the exact in-tree code is
# exercised; no HVF entitlement is needed because the test only manipulates
# mmap and PROT_NONE. The codesign step is skipped for the same reason.
$(BUILD_DIR)/test-proctitle-host: $(BUILD_DIR)/test-proctitle-host.o \
		$(BUILD_DIR)/runtime/proctitle.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the shebang parsing host test (native macOS binary)
$(BUILD_DIR)/test-shebang-host: $(BUILD_DIR)/test-shebang-host.o \
		$(BUILD_DIR)/core/elf.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI reference parser unit test (native macOS binary).
## Pure C, no HVF, no codesign required.
$(BUILD_DIR)/test-oci-ref: $(BUILD_DIR)/test-oci-ref.o $(BUILD_DIR)/oci/ref.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI digest unit test (native macOS binary). Pure C, no HVF.
$(BUILD_DIR)/test-oci-digest: $(BUILD_DIR)/test-oci-digest.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI blob store unit test (native macOS binary). Pure C, no HVF.
$(BUILD_DIR)/test-oci-blob-store: $(BUILD_DIR)/test-oci-blob-store.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI manifest / index / config parser unit test (native, no HVF).
$(BUILD_DIR)/test-oci-manifest: $(BUILD_DIR)/test-oci-manifest.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(CJSON_LIBS)

## Build the OCI local store unit test (native macOS, no HVF). Pure C; links
## against the store wrapper plus its blob-store, digest, and cJSON deps.
## cJSON is required because store.c now reads / writes index.json.
$(BUILD_DIR)/test-oci-store: $(BUILD_DIR)/test-oci-store.o $(BUILD_DIR)/oci/store.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/digest-set.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/origin-meta.o $(BUILD_DIR)/oci/volume-list.o $(BUILD_DIR)/oci/ref.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(CJSON_LIBS)

## Build the OCI inspect renderer unit test (native macOS, no HVF). Pure
## offline: no fetcher, no mock server, no libcurl. Pre-populates the store
## via oci_blob_store_put_bytes + oci_store_put_ref.
$(BUILD_DIR)/test-oci-inspect: $(BUILD_DIR)/test-oci-inspect.o $(BUILD_DIR)/oci/inspect.o $(BUILD_DIR)/oci/dedup-metrics.o $(BUILD_DIR)/oci/store.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/digest-set.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/origin-meta.o $(BUILD_DIR)/oci/volume-list.o $(BUILD_DIR)/oci/ref.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(CJSON_LIBS)

## Build the OCI cross-image dedup metrics unit test (native macOS, no HVF).
## Drives oci_dedup_metrics_compute against scratch stores hand-populated
## via oci_blob_store_put_bytes + oci_store_put_ref. Same dependency set
## as test-oci-inspect, plus oci/dedup-metrics.o.
$(BUILD_DIR)/test-oci-dedup-metrics: $(BUILD_DIR)/test-oci-dedup-metrics.o $(BUILD_DIR)/oci/dedup-metrics.o $(BUILD_DIR)/oci/store.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/digest-set.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/origin-meta.o $(BUILD_DIR)/oci/volume-list.o $(BUILD_DIR)/oci/ref.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(CJSON_LIBS)

## Build the OCI rebuild-cache unit test (native macOS, no HVF). Drives
## oci_rebuild_cache against scratch stores hand-populated via oci_origin_write
## into a fixture <volume>/images/sha256-<hex>/ tree, then asserts that
## <store>/layers/stacks/sha256/<chain>/ entries are created (commit) or left
## absent (dry-run). Same dependency set as test-oci-store plus oci/rebuild-
## cache.o.
$(BUILD_DIR)/test-oci-rebuild-cache: $(BUILD_DIR)/test-oci-rebuild-cache.o $(BUILD_DIR)/oci/rebuild-cache.o $(BUILD_DIR)/oci/store.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/digest-set.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/origin-meta.o $(BUILD_DIR)/oci/volume-list.o $(BUILD_DIR)/oci/ref.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(CJSON_LIBS)

## Build the OCI store-wide status unit test (native macOS, no HVF). Drives
## oci_status_compute against scratch stores hand-populated via
## stage_image / oci_origin_write fixture helpers and asserts the aggregated
## struct fields (pin entries, unpacked entries, reachable + populated
## ratios, store totals). Same dependency set as test-oci-store plus
## oci/status.o.
$(BUILD_DIR)/test-oci-status: $(BUILD_DIR)/test-oci-status.o $(BUILD_DIR)/oci/status.o $(BUILD_DIR)/oci/store.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/digest-set.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/origin-meta.o $(BUILD_DIR)/oci/volume-list.o $(BUILD_DIR)/oci/ref.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(CJSON_LIBS)

## Build the OCI runspec unit test (native macOS, no HVF). Merges
## image-config runtime block + CLI overrides; the rootfs-driven
## symbolic-User cases write /etc/passwd and /etc/group fixtures under
## /tmp, so the link island pulls in oci/user-lookup.o.
$(BUILD_DIR)/test-oci-runspec: $(BUILD_DIR)/test-oci-runspec.o $(BUILD_DIR)/oci/runspec.o $(BUILD_DIR)/oci/user-lookup.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI User-field resolver unit test (native macOS, no HVF).
## Pure C; the test builds scratch /tmp rootfses with synthetic
## /etc/passwd / /etc/group and drives oci_user_lookup across the seven
## OCI image-spec User shapes plus the policy edges.
$(BUILD_DIR)/test-oci-user: $(BUILD_DIR)/test-oci-user.o $(BUILD_DIR)/oci/user-lookup.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI path-resolve unit test (native macOS, no HVF). Touches
## the host filesystem to build a small fake sysroot tree and drives
## oci_path_resolve through realpath / stat / symlink-follow scenarios.
## Pure C; no libcurl, no zstd, no HVF.
$(BUILD_DIR)/test-oci-path-resolve: $(BUILD_DIR)/test-oci-path-resolve.o $(BUILD_DIR)/oci/path-resolve.o $(BUILD_DIR)/core/elf.o $(BUILD_DIR)/debug/log.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI run orchestrator unit test (native macOS, no HVF). Links
## the same OCI graph the unpack test pulls in, plus oci/run.o,
## oci/runspec.o, and oci/path-resolve.o. Does NOT link core/launch.o:
## the test ships an in-file elfuse_launch stub that aborts when called,
## and every case installs a launch hook via oci_run_set_launch_for_testing
## before invoking oci_run, so the real VM bring-up never runs from a test.
$(BUILD_DIR)/test-oci-run: $(BUILD_DIR)/test-oci-run.o $(BUILD_DIR)/oci/run.o $(BUILD_DIR)/oci/runspec.o $(BUILD_DIR)/oci/user-lookup.o $(BUILD_DIR)/oci/path-resolve.o $(BUILD_DIR)/oci/runtime-files.o $(BUILD_DIR)/oci/unpack.o $(BUILD_DIR)/oci/volume.o $(BUILD_DIR)/oci/volume-list.o $(BUILD_DIR)/oci/clone-rootfs.o $(BUILD_DIR)/oci/layer-apply.o $(BUILD_DIR)/oci/layer-meta.o $(BUILD_DIR)/oci/origin-meta.o $(BUILD_DIR)/oci/tar.o $(BUILD_DIR)/oci/store.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/digest-set.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/ref.o $(BUILD_DIR)/core/elf.o $(BUILD_DIR)/core/sysroot.o $(BUILD_DIR)/debug/log.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(LIBARCHIVE_LIBS) $(CJSON_LIBS)

## Build the OCI runtime-files injection unit test (native macOS, no HVF).
## Pure C; the test drives oci_runtime_files_inject against scratch
## /tmp/elfuse-rf-* run directories and verifies the synthesised
## /etc/{resolv.conf,hosts,hostname} content.
$(BUILD_DIR)/test-oci-runtime-files: $(BUILD_DIR)/test-oci-runtime-files.o $(BUILD_DIR)/oci/runtime-files.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI fixture builder (used by the OCI compat tests). Standalone tool
## that synthesises a complete OCI store from uncompressed-tar layers
## plus image-config flags. Used by tests/test-oci-compat.sh and
## available standalone for one-off "shape an image from local files"
## experiments.
$(BUILD_DIR)/oci-fixture-builder: $(BUILD_DIR)/lib/oci-fixture-builder.o $(BUILD_DIR)/oci/store.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/digest-set.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/origin-meta.o $(BUILD_DIR)/oci/volume-list.o $(BUILD_DIR)/oci/ref.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(CJSON_LIBS)

## tar.c is the only translation unit in elfuse that includes libarchive
## headers; scope the keg-only include path to it.
$(BUILD_DIR)/oci/tar.o: CFLAGS += $(LIBARCHIVE_CFLAGS)

## Build the OCI sidecar metadata unit test (native macOS, no HVF). Pure
## C; links against cJSON for the JSON round-trip plus the layer-meta
## translation unit.
$(BUILD_DIR)/test-oci-meta: $(BUILD_DIR)/test-oci-meta.o $(BUILD_DIR)/oci/layer-meta.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(CJSON_LIBS)

## Build the OCI origin sidecar unit test (native macOS, no HVF). Drives
## oci_origin_write against a tmpdir and verifies the resulting
## .elfuse-origin.json by parsing it back through cJSON.
$(BUILD_DIR)/test-oci-origin: $(BUILD_DIR)/test-oci-origin.o $(BUILD_DIR)/oci/origin-meta.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(CJSON_LIBS)

## Build the OCI layer applier unit test (native macOS, no HVF). Builds
## tar payloads in memory, drives them through oci_layer_apply into a
## tmp tree, and verifies filesystem state via lstat/readlink.
$(BUILD_DIR)/test-oci-layer-apply: $(BUILD_DIR)/test-oci-layer-apply.o $(BUILD_DIR)/oci/layer-apply.o $(BUILD_DIR)/oci/layer-meta.o $(BUILD_DIR)/oci/tar.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(LIBARCHIVE_LIBS) $(CJSON_LIBS)

## Build the OCI volume bootstrap unit test (native macOS, no HVF).
## Default-volume test is gated behind OCI_VOLUME_TEST=1 because it
## costs ~150 ms of hdiutil orchestration on first run. Links
## src/core/sysroot.o for the hdiutil wrappers PR #33 introduced.
$(BUILD_DIR)/test-oci-volume: $(BUILD_DIR)/test-oci-volume.o $(BUILD_DIR)/oci/volume.o $(BUILD_DIR)/core/sysroot.o $(BUILD_DIR)/debug/log.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI clone-rootfs unit test (native macOS, no HVF). The
## test skips itself if clonefile returns ENOTSUP (non-APFS scratch).
$(BUILD_DIR)/test-oci-clone: $(BUILD_DIR)/test-oci-clone.o $(BUILD_DIR)/oci/clone-rootfs.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI unpack orchestrator integration smoke (native macOS,
## no HVF). Pulls in the full OCI stack so the dependency edges
## between modules are exercised at link time.
$(BUILD_DIR)/test-oci-unpack: $(BUILD_DIR)/test-oci-unpack.o $(BUILD_DIR)/oci/unpack.o $(BUILD_DIR)/oci/volume.o $(BUILD_DIR)/oci/volume-list.o $(BUILD_DIR)/oci/clone-rootfs.o $(BUILD_DIR)/oci/layer-apply.o $(BUILD_DIR)/oci/layer-meta.o $(BUILD_DIR)/oci/origin-meta.o $(BUILD_DIR)/oci/tar.o $(BUILD_DIR)/oci/store.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/digest-set.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/ref.o $(BUILD_DIR)/core/sysroot.o $(BUILD_DIR)/debug/log.o $(BUILD_DIR)/oci/util.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(LIBARCHIVE_LIBS) $(CJSON_LIBS)

# Guest test binaries (cross-compiled, aarch64-linux)
# Only used when GUEST_TEST_BINARIES is not set.

ifndef GUEST_TEST_BINARIES
$(BUILD_DIR)/test-hello: tests/hello.S tests/simple.ld | $(BUILD_DIR)
	@echo "  AS      tests/hello.S"
	$(Q)$(BAREMETAL_CROSS)as -o $(BUILD_DIR)/test-hello.o tests/hello.S
	@echo "  LD      $@"
	$(Q)$(BAREMETAL_CROSS)ld -T tests/simple.ld -o $@ $(BUILD_DIR)/test-hello.o

# Pattern rule: cross-compile tests/*.c to static aarch64-linux binaries
# -D_GNU_SOURCE exposes pipe2/dup3/O_DIRECT/etc. on glibc (musl exposes them by default)
$(BUILD_DIR)/%: tests/%.c | $(BUILD_DIR)
	@echo "  CROSS   $<"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $<

# test-pthread needs -lpthread
$(BUILD_DIR)/test-pthread: tests/test-pthread.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-osync-requeue drives a raw FUTEX_REQUEUE against a plain-FUTEX_WAIT
# waiter (musl unlock_requeue pattern) to guard the os_sync wake-at-source
# degradation; needs -lpthread.
$(BUILD_DIR)/test-osync-requeue: tests/test-osync-requeue.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-scm-creds blocks accept in a pthread while the listener option changes.
$(BUILD_DIR)/test-scm-creds: tests/test-scm-creds.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-fault-signal-mt spawns pthreads that each take recoverable SIGSEGVs to
# stress synchronous-fault delivery routing in a multi-threaded guest.
$(BUILD_DIR)/test-fault-signal-mt: tests/test-fault-signal-mt.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-shim-cred-race spawns a pthread reader while the main thread
# toggles setresuid; the reader spins on the identity fast path.
$(BUILD_DIR)/test-shim-cred-race: tests/test-shim-cred-race.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-mprotect-mt stresses multi-vCPU mprotect under concurrent reader
# threads to surface stale-TLB regressions.
$(BUILD_DIR)/test-mprotect-mt: tests/test-mprotect-mt.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-shim-urandom-smp spawns N pthreads racing on a shared FD_URANDOM
# slot to exercise the shim's LDXR/STXR head-advance under contention.
$(BUILD_DIR)/test-shim-urandom-smp: tests/test-shim-urandom-smp.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-shim-urandom-toctou races mprotect(PROT_NONE) against urandom
# reads to exercise the EL1 data abort recovery path. Needs pthreads.
$(BUILD_DIR)/test-shim-urandom-toctou: tests/test-shim-urandom-toctou.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-fuse-basic runs a guest daemon thread and consumer in one process
$(BUILD_DIR)/test-fuse-basic: tests/test-fuse-basic.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-sched-policy spawns a pthread to verify per-thread TID lookup
$(BUILD_DIR)/test-sched-policy: tests/test-sched-policy.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-signalfd-hardening needs -lpthread for the worker-thread tid
# regression case in test_rt_sigqueueinfo_rejects_thread_tid.
$(BUILD_DIR)/test-signalfd-hardening: tests/test-signalfd-hardening.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-futex-waitv needs -lpthread for the host wake-thread used to unblock
# the main thread's futex_waitv.
$(BUILD_DIR)/test-futex-waitv: tests/test-futex-waitv.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-fork-lowbase must be a non-PIE ET_EXEC linked below ELF_DEFAULT_BASE so
# nested forks exercise elf_load_min preservation across fork IPC.
$(BUILD_DIR)/test-fork-lowbase: tests/test-fork-lowbase.c | $(BUILD_DIR)
	@echo "  CROSS   $< (low-base ET_EXEC)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -no-pie \
		-Wl,-Ttext-segment=0x200000 -o $@ $<

# test-lowbase-mem variants must be non-PIE ET_EXEC binaries linked below
# ELF_DEFAULT_BASE so mprotect/munmap exercise the old low-address reject
# window at two offsets.
$(BUILD_DIR)/test-lowbase-mem-200000: tests/test-lowbase-mem.c | $(BUILD_DIR)
	@echo "  CROSS   $< (low-base ET_EXEC @0x200000)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -no-pie \
		-Wl,-Ttext-segment=0x200000 -o $@ $<

$(BUILD_DIR)/test-lowbase-mem-300000: tests/test-lowbase-mem.c | $(BUILD_DIR)
	@echo "  CROSS   $< (low-base ET_EXEC @0x300000)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -no-pie \
		-Wl,-Ttext-segment=0x300000 -o $@ $<

# bench-hot-guard-glibc is the dynamic-glibc twin of bench-hot-guard.
# Built only when the cross-glibc toolchain ships its own sysroot
# (so a host without that toolchain can still run the rest of the
# suite). Linked without -static so glibc resolves time / urandom
# syscalls through the vDSO trampoline -- which is exactly what the
# guardrail script verifies against the 50 ns / 200 ns ceilings.
ifneq ($(wildcard $(LINUX_TOOLCHAIN)/aarch64-unknown-linux-gnu/sysroot/.),)
# -DGUARD_USE_LIBC_CG switches the bench's clock_gettime case from a
# direct vDSO trampoline call to the libc wrapper, so the dynamic-glibc
# build measures glibc's actual routing decision. A regression in the
# NT_GNU_ABI_TAG note or LINUX_2.6.39 versioning would push this
# measurement from ~7 ns up to SVC time (~2000 ns) and fail the
# guardrail.
$(BUILD_DIR)/bench-hot-guard-glibc: tests/bench-hot-guard.c | $(BUILD_DIR)
	@echo "  CROSS   $< (dynamic glibc)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -DGUARD_USE_LIBC_CG=1 -O2 \
		-o $@ $<
endif

endif

include mk/tests.mk
include mk/analysis.mk
include mk/help.mk
