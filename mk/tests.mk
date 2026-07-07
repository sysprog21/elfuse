# Test targets

.PHONY: test-hello test-all check check-syscall-coverage test-gdbstub test-coreutils test-busybox \
        test-runtime-stats \
        test-static-bins \
        test-dynamic test-dynamic-coreutils test-glibc-dynamic \
        test-glibc-coreutils test-perf \
        test-rosetta-cli test-rosetta-statics test-rosetta-failure-modes \
        test-rosetta-alpine test-rosetta-audit test-rosetta-jit \
        test-rosetta-glibc test-rosetta-madvise test-rosetta-msync \
        test-rosetta-mremap test-rosetta-all bench-rosetta \
        test-matrix test-matrix-elfuse-aarch64 test-matrix-qemu-aarch64 \
        test-full test-multi-vcpu test-rwx test-sysroot-rename \
        test-case-collision test-case-collision-fallback test-getdents64-overlong \
        test-sysroot-host-fallback test-sysroot-case-exact \
        test-sysroot-create-paths test-fork-ipc-protocol-host test-identity-override-host \
        test-proctitle-host test-proctitle-low-stack \
        test-sysroot-procfs-exec test-timeout-disable test-fuse-alpine \
        test-sysroot-nofollow test-sysroot-chdir perf

## Build and run the assembly hello world test
test-hello: $(ELFUSE_BIN) $(TEST_HELLO_DEP)
	@printf "$(BLUE)▸ Running$(RESET) test-hello\n"
	$(ELFUSE_BIN) $(TEST_DIR)/test-hello

## Verify dispatch.tbl coverage of the kernel-supported syscall set
check-syscall-coverage:
	@python3 scripts/check-syscall-coverage.py

define RUN_OPTIONAL_SKIP77
	@set -e; \
	rc=0; \
	$(1) || rc=$$?; \
	if [ "$$rc" = 77 ]; then \
		printf "$(YELLOW)SKIP$(RESET) %s\n" "$(2)"; \
	elif [ "$$rc" != 0 ]; then \
		exit "$$rc"; \
	fi
endef

## Run the unit test suite plus busybox applet validation
check: $(ELFUSE_BIN) $(TEST_DEPS) check-syscall-coverage \
		$(BUILD_DIR)/test-tlbi-encoder-host \
		$(BUILD_DIR)/test-fork-ipc-protocol-host \
		$(BUILD_DIR)/test-identity-override-host
	@bash tests/driver.sh -e $(ELFUSE_BIN) -d $(TEST_DIR) -v
	@printf "\n$(BLUE)━━━ TLBI RVAE1IS encoder unit test ━━━$(RESET)\n"
	@$(BUILD_DIR)/test-tlbi-encoder-host
	@printf "\n$(BLUE)━━━ fork IPC protocol identity unit test ━━━$(RESET)\n"
	@$(BUILD_DIR)/test-fork-ipc-protocol-host
	@printf "\n$(BLUE)━━━ identity override unit test ━━━$(RESET)\n"
	@$(BUILD_DIR)/test-identity-override-host
	@printf "\n$(BLUE)━━━ shebang parser unit test ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-shebang-host
	@printf "\n$(BLUE)━━━ proctitle argv-tail regression ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-proctitle-host
	@printf "\n$(BLUE)━━━ proctitle low-stack regression ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-proctitle-low-stack
	@printf "\n$(BLUE)━━━ busybox applet validation ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-busybox
	@printf "\n$(BLUE)━━━ sysroot procfs exec validation ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-sysroot-procfs-exec
	@printf "\n$(BLUE)━━━ getdents64 overlong-UTF-8 dirent skip ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-getdents64-overlong
	@printf "\n$(BLUE)━━━ sysroot host-fallback validation ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-sysroot-host-fallback
	@printf "\n$(BLUE)━━━ sysroot byte-exact lookup validation ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-sysroot-case-exact
	@printf "\n$(BLUE)━━━ Alpine sysroot FUSE validation ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-fuse-alpine
	@printf "\n$(BLUE)━━━ timeout=0 validation ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-timeout-disable
	@printf "\n$(BLUE)━━━ rosetta CLI gating ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-rosetta-cli
	@printf "\n$(BLUE)━━━ hot-syscall guardrail ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-bench-guardrail
	@printf "\n$(BLUE)━━━ runtime-stats output validation ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-runtime-stats

## Hot-syscall performance guardrail: ensure getpid, libc clock_gettime,
## and 1-byte /dev/urandom reads stay under their TODO ns/op ceilings.
## Builds the dynamic-glibc variant opportunistically; the script skips
## that arm when the cross-toolchain sysroot is missing.
BENCH_GUARDRAIL_DEPS := $(ELFUSE_BIN)
BENCH_GUARDRAIL_REQUIRE_STATIC := 0
ifndef GUEST_TEST_BINARIES
  BENCH_GUARDRAIL_DEPS += $(BUILD_DIR)/bench-hot-guard
  BENCH_GUARDRAIL_REQUIRE_STATIC := 1
  ifneq ($(wildcard $(LINUX_TOOLCHAIN)/aarch64-unknown-linux-gnu/sysroot/.),)
    BENCH_GUARDRAIL_DEPS += $(BUILD_DIR)/bench-hot-guard-glibc
  endif
endif
test-bench-guardrail: $(BENCH_GUARDRAIL_DEPS)
	@ELFUSE="$(ELFUSE_BIN)" \
	    BENCH_GUARDRAIL_DIR="$(TEST_DIR)" \
	    BENCH_GUARDRAIL_REQUIRE_STATIC="$(BENCH_GUARDRAIL_REQUIRE_STATIC)" \
	    LINUX_TOOLCHAIN="$(LINUX_TOOLCHAIN)" \
	    bash tests/test-bench-guardrail.sh

test-sysroot-rename: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-rename
	@set -e; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"; rm -f /tmp/elfuse-sysroot-rename-dst.txt' EXIT; \
	mkdir -p "$$tmpdir/tmp"; \
	printf 'inside-sysroot\n' > "$$tmpdir/tmp/elfuse-sysroot-rename-src.txt"; \
	rm -f /tmp/elfuse-sysroot-rename-dst.txt; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-sysroot-rename; \
	if [ -f "$$tmpdir/tmp/elfuse-sysroot-rename-src.txt" ]; then \
		printf "$(RED)FAIL$(RESET) rename did not remove source from sysroot\n"; \
		exit 1; \
	fi; \
	if [ -e /tmp/elfuse-sysroot-rename-dst.txt ]; then \
		printf "$(RED)FAIL$(RESET) rename escaped sysroot to host /tmp\n"; \
		exit 1; \
	fi

test-sysroot-nofollow: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-nofollow
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	mkdir -p "$$tmpdir/tmp"; \
	ln -sf /outside-target "$$tmpdir/tmp/elfuse-sysroot-nofollow-link"; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-sysroot-nofollow

test-sysroot-chdir: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-chdir
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	mkdir -p "$$tmpdir/bin" "$$tmpdir/lib" "$$tmpdir/lib/elfuse-sysroot-shadow"; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-sysroot-chdir

test-case-collision: $(ELFUSE_BIN) $(BUILD_DIR)/test-case-collision
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	$(ELFUSE_BIN) --create-sysroot "$$tmpdir/case-sysroot" $(BUILD_DIR)/test-case-collision

test-case-collision-fallback: $(ELFUSE_BIN) $(BUILD_DIR)/test-case-collision
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-case-collision

## Host paths outside the sysroot must stay reachable when the sysroot is
## case-insensitive (sidecar active): the sidecar walk defers to the
## resolver's host-literal fallback instead of vetoing it with ENOENT.
## Regression test for the test-matrix "musl dyn" coreutils failures.
test-sysroot-host-fallback: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-host-fallback
	@set -e; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	sysroot="$$tmpdir/sysroot"; \
	hostdir="$$tmpdir/host-data"; \
	mkdir -p "$$sysroot" "$$hostdir"; \
	first=$${tmpdir#/}; first=$${first%%/*}; \
	mkdir -p "$$sysroot/$$first"; \
	printf 'host-visible\n' > "$$hostdir/hello.txt"; \
	mirror="$$tmpdir/mirrored"; \
	mkdir -p "$$mirror" "$$sysroot$$mirror"; \
	printf 'host-final\n' > "$$mirror/final.txt"; \
	printf 'host-loses\n' > "$$mirror/both.txt"; \
	printf 'sysroot-wins\n' > "$$sysroot$$mirror/both.txt"; \
	$(ELFUSE_BIN) --sysroot "$$sysroot" \
	    $(BUILD_DIR)/test-sysroot-host-fallback \
	    "$$hostdir" "$$mirror/final.txt" "$$mirror/both.txt"

## Wrong-case (and wrong-normalization) lookups must fail with ENOENT:
## Linux treats names as byte strings, while APFS resolves them case- and
## normalization-insensitively. The sidecar walk verifies the on-disk
## spelling of every unmapped component instead of trusting the folded
## probe. Stages exact-case fixtures host-side; the guest asserts folded
## spellings do not resolve. The normalization probes require the sidecar,
## so the guest skips them when the staging volume is case-sensitive.
test-sysroot-case-exact: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-case-exact
	@set -e; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	sysroot="$$tmpdir/sysroot"; \
	mkdir -p "$$sysroot/data/sub"; \
	printf 'exact\n' > "$$sysroot/data/Makefile"; \
	printf 'sub\n' > "$$sysroot/data/sub/f.txt"; \
	printf 'nfc\n' > "$$sysroot/data/caf$$(printf '\303\251')"; \
	mode=cs; \
	if [ -e "$$sysroot/data/MAKEFILE" ]; then mode=ci; fi; \
	$(ELFUSE_BIN) --sysroot "$$sysroot" \
	    $(BUILD_DIR)/test-sysroot-case-exact "$$mode"; \
	if [ ! -e "$$sysroot/data/Makefile" ]; then \
		printf "$(RED)FAIL$(RESET) wrong-case op removed the exact entry\n"; \
		exit 1; \
	fi

# Build APFS-side dirents whose UTF-8 byte length exceeds Linux
# NAME_MAX (255). 89 copies of U+3042 (3-byte UTF-8) plus a 1-byte
# ASCII tag = 268 bytes per name; the guest cannot forge this via
# openat (NAME_MAX is enforced), so the harness stages it host-side
# and the guest scans the listing. Five overlong files plus one
# normal entry: with a one-entry-per-call buffer on the guest side,
# any APFS hash ordering puts an overlong entry in a position where
# pre-fix code returned -ENAMETOOLONG to userspace.
test-getdents64-overlong: $(ELFUSE_BIN) $(BUILD_DIR)/test-getdents64-overlong
	@set -e; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	mkdir -p "$$tmpdir/fixture"; \
	: > "$$tmpdir/fixture/expected.txt"; \
	for tag in a b c d e; do \
		overlong=$$(printf '\343\201\202%.0s' $$(seq 1 89))$$tag; \
		: > "$$tmpdir/fixture/$$overlong"; \
	done; \
	$(ELFUSE_BIN) $(BUILD_DIR)/test-getdents64-overlong "$$tmpdir/fixture"

test-sysroot-create-paths: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-create-paths
	@set -e; \
	tmpdir=$$(mktemp -d); \
	guest_tmp="/tmp/elfuse-sysroot-create-paths/file.txt"; \
	mounted_tmp="$$tmpdir/case-sysroot/tmp/elfuse-sysroot-create-paths/file.txt"; \
	host_out_dir="$$tmpdir/host-out"; \
	host_out="$$host_out_dir/result.txt"; \
	trap 'rm -rf "$$tmpdir"; rm -rf /tmp/elfuse-sysroot-create-paths' EXIT; \
	rm -rf /tmp/elfuse-sysroot-create-paths; \
	mkdir -p "$$host_out_dir"; \
	$(ELFUSE_BIN) --create-sysroot "$$tmpdir/case-sysroot" $(BUILD_DIR)/test-sysroot-create-paths "$$guest_tmp" "$$mounted_tmp" "$$host_out" "$$tmpdir/case-sysroot"; \
	if [ -e "$$guest_tmp" ]; then \
		printf "$(RED)FAIL$(RESET) guest /tmp escaped to host /tmp\n"; \
		exit 1; \
	fi; \
	if [ ! -f "$$host_out" ]; then \
		printf "$(RED)FAIL$(RESET) host fallback path was not created\n"; \
		exit 1; \
	fi; \
	if ! grep -q "host-fallback" "$$host_out"; then \
		printf "$(RED)FAIL$(RESET) host fallback file contents mismatch\n"; \
		exit 1; \
	fi

test-sysroot-procfs-exec: $(ELFUSE_BIN) $(BUILD_DIR)/test-procfs-exec
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	mkdir -p "$$tmpdir/bin"; \
	cp $(BUILD_DIR)/test-procfs-exec "$$tmpdir/bin/test-procfs-exec"; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" "$$tmpdir/bin/test-procfs-exec"

test-timeout-disable: $(ELFUSE_BIN) $(TEST_HELLO_DEP)
	@$(ELFUSE_BIN) --timeout 0 $(TEST_DIR)/test-hello > /dev/null

## Run GDB stub integration tests (LLDB <-> elfuse gdbstub)
test-gdbstub: $(ELFUSE_BIN) $(TEST_DIR)/test-hello
	@bash tests/test-gdbstub.sh -e $(ELFUSE_BIN) -v

## Run Rosetta CLI gating regressions without requiring Rosetta runtime support
test-rosetta-cli: $(ELFUSE_BIN)
	@bash tests/test-rosetta-cli.sh $(ELFUSE_BIN)

## Smoke test x86_64 statics through Rosetta. Requires Rosetta-for-Linux
## installed on the host and the Alpine x86_64 fixture tree staged via
## INCLUDE_X86_64=1 bash tests/fetch-fixtures.sh. Skips cleanly otherwise.
test-rosetta-statics: $(ELFUSE_BIN)
	$(call RUN_OPTIONAL_SKIP77,bash tests/test-rosetta-statics.sh $(ELFUSE_BIN),test-rosetta-statics)

## Probe known-unsupported scenarios (dynamic x86_64, mid-process execve,
## --gdb on x86_64, --no-rosetta). Verifies the failure path emits a
## stable error rather than crashing or succeeding silently.
test-rosetta-failure-modes: $(ELFUSE_BIN)
	@bash tests/test-rosetta-failure-modes.sh $(ELFUSE_BIN)

## Alpine x86_64 file-I/O + text-pipeline coverage. Lifts the matrix's
## busybox-applet style tests against the Alpine staticbin tree but stays
## lightweight enough for the rosetta-all aggregate. Skips cleanly when
## fixtures or Rosetta-for-Linux are missing.
test-rosetta-alpine: $(ELFUSE_BIN)
	$(call RUN_OPTIONAL_SKIP77,bash tests/test-rosetta-alpine.sh $(ELFUSE_BIN),test-rosetta-alpine)

test-rosetta-audit: $(ELFUSE_BIN)
	$(call RUN_OPTIONAL_SKIP77,bash tests/test-rosetta-audit.sh $(ELFUSE_BIN),test-rosetta-audit)

test-rosetta-jit: $(ELFUSE_BIN)
	$(call RUN_OPTIONAL_SKIP77,bash tests/test-rosetta-jit.sh $(ELFUSE_BIN),test-rosetta-jit)

test-rosetta-glibc: $(ELFUSE_BIN)
	$(call RUN_OPTIONAL_SKIP77,bash tests/test-rosetta-glibc.sh $(ELFUSE_BIN),test-rosetta-glibc)

test-rosetta-madvise: $(ELFUSE_BIN)
	$(call RUN_OPTIONAL_SKIP77,bash tests/test-rosetta-madvise.sh $(ELFUSE_BIN),test-rosetta-madvise)

test-rosetta-msync: $(ELFUSE_BIN)
	$(call RUN_OPTIONAL_SKIP77,bash tests/test-rosetta-msync.sh $(ELFUSE_BIN),test-rosetta-msync)

test-rosetta-mremap: $(ELFUSE_BIN)
	$(call RUN_OPTIONAL_SKIP77,bash tests/test-rosetta-mremap.sh $(ELFUSE_BIN),test-rosetta-mremap)

## Run every Rosetta-specific test target in sequence.
test-rosetta-all: test-rosetta-cli test-rosetta-failure-modes \
                  test-rosetta-statics test-rosetta-alpine \
                  test-rosetta-audit test-rosetta-jit test-rosetta-glibc \
                  test-rosetta-madvise test-rosetta-msync test-rosetta-mremap

## Wall-clock bench harness for x86_64-via-Rosetta workloads. Prints
## best-of-N samples plus the aarch64 reference where available. Set
## BENCH_ITERS=<n> to change sample count (default 5).
BENCH_ITERS ?= 5
bench-rosetta: $(ELFUSE_BIN)
	$(call RUN_OPTIONAL_SKIP77,bash tests/bench-rosetta.sh $(ELFUSE_BIN) $(BENCH_ITERS),bench-rosetta)

## Alias for check (backward compat)
test-all: check

# Coreutils integration test
FIXTURES_DIR ?= $(CURDIR)/externals/test-fixtures

ifeq ($(origin GUEST_COREUTILS), undefined)
  ifneq ($(wildcard $(FIXTURES_DIR)/aarch64-musl/dyn-bin),)
    GUEST_COREUTILS := $(FIXTURES_DIR)/aarch64-musl/dyn-bin
  endif
endif

ifeq ($(origin GUEST_BUSYBOX), undefined)
  ifneq ($(wildcard $(FIXTURES_DIR)/aarch64-musl/staticbin/bin/busybox),)
    GUEST_BUSYBOX := $(FIXTURES_DIR)/aarch64-musl/staticbin/bin/busybox
  endif
endif

ifeq ($(origin GUEST_STATIC_BINS), undefined)
  ifneq ($(wildcard $(FIXTURES_DIR)/aarch64-musl/dyn-bin),)
    GUEST_STATIC_BINS := $(FIXTURES_DIR)/aarch64-musl/dyn-bin
  endif
endif

ifeq ($(origin GUEST_SYSROOT), undefined)
  ifneq ($(wildcard $(FIXTURES_DIR)/rootfs),)
    GUEST_SYSROOT := $(FIXTURES_DIR)/rootfs
  endif
endif

ifeq ($(origin GUEST_DYNAMIC_COREUTILS), undefined)
  ifneq ($(wildcard $(FIXTURES_DIR)/aarch64-musl/dyn-bin),)
    GUEST_DYNAMIC_COREUTILS := $(FIXTURES_DIR)/aarch64-musl/dyn-bin
  endif
endif

# Path to static aarch64-linux coreutils bin directory.
# Auto-detected from GUEST_COREUTILS; override with COREUTILS_BIN=...
ifdef GUEST_COREUTILS
  ifneq ($(wildcard $(GUEST_COREUTILS)/bin),)
    COREUTILS_BIN ?= $(GUEST_COREUTILS)/bin
  else
    COREUTILS_BIN ?= $(GUEST_COREUTILS)
  endif
endif

## Run GNU coreutils 9.9 integration tests (104 tools)
test-coreutils: $(ELFUSE_BIN)
	@if [ ! -d "$(COREUTILS_BIN)" ]; then \
		printf "$(RED)✗ Coreutils not found.$(RESET) Set COREUTILS_BIN=/path/to/bin.\n"; \
		exit 1; \
	fi
	@if [ "$(COREUTILS_BIN)" = "$(FIXTURES_DIR)/aarch64-musl/dyn-bin" ]; then \
		COREUTILS_PROFILE=smoke bash tests/test-coreutils.sh $(ELFUSE_BIN) $(COREUTILS_BIN) $(SYSROOT_DIR); \
	elif [ -n "$(SYSROOT_DIR)" ] && [ -d "$(SYSROOT_DIR)" ]; then \
		bash tests/test-coreutils.sh $(ELFUSE_BIN) $(COREUTILS_BIN) $(SYSROOT_DIR); \
	else \
		bash tests/test-coreutils.sh $(ELFUSE_BIN) $(COREUTILS_BIN); \
	fi

# Busybox integration test
ifneq ($(wildcard $(BUILD_DIR)/busybox),)
  BUSYBOX_BIN ?= $(BUILD_DIR)/busybox
else ifdef GUEST_BUSYBOX
  ifneq ($(wildcard $(GUEST_BUSYBOX)/bin/busybox),)
    BUSYBOX_BIN ?= $(GUEST_BUSYBOX)/bin/busybox
  else
    BUSYBOX_BIN ?= $(GUEST_BUSYBOX)
  endif
else
  BUSYBOX_BIN ?= $(BUILD_DIR)/busybox
endif

BUSYBOX_SUITE ?= sid
BUSYBOX_PACKAGE_PAGE ?= https://packages.debian.org/$(BUSYBOX_SUITE)/busybox-static
BUSYBOX_DOWNLOAD_PAGE ?= https://packages.debian.org/$(BUSYBOX_SUITE)/arm64/busybox-static/download

ifeq ($(BUSYBOX_BIN),$(BUILD_DIR)/busybox)
  BUSYBOX_DEPS := $(BUILD_DIR)/busybox
else
  BUSYBOX_DEPS :=
endif

$(BUILD_DIR)/busybox: | $(BUILD_DIR)
	@printf "$(BLUE)▸ Downloading$(RESET) busybox-static (arm64) from $(BUSYBOX_PACKAGE_PAGE)\n"
	@tmpdir="$(BUILD_DIR)/busybox-static.tmp"; \
	rm -rf "$$tmpdir"; \
	mkdir -p "$$tmpdir"; \
	package_page="$$tmpdir/package.html"; \
	download_page="$$tmpdir/download.html"; \
	deb="$$tmpdir/busybox-static.deb"; \
	curl -fsSL "$(BUSYBOX_PACKAGE_PAGE)" -o "$$package_page"; \
	download_url=$$(sed -n 's/.*href="\([^"]*\/arm64\/busybox-static\/download\)".*/\1/p' "$$package_page" | head -n 1); \
	if [ -z "$$download_url" ]; then \
		download_url="$(BUSYBOX_DOWNLOAD_PAGE)"; \
	fi; \
	case "$$download_url" in \
		http*) ;; \
		*) download_url="https://packages.debian.org$$download_url" ;; \
	esac; \
	curl -fsSL "$$download_url" -o "$$download_page"; \
	deb_url=$$(sed -n 's/.*href="\([^"]*busybox-static_[^"]*_arm64\.deb\)".*/\1/p' "$$download_page" | head -n 1); \
	if [ -z "$$deb_url" ]; then \
		printf "$(RED)✗ Could not find busybox-static .deb link on %s$(RESET)\n" "$$download_url"; \
		exit 1; \
	fi; \
	case "$$deb_url" in \
		http*) ;; \
		//*) deb_url="https:$$deb_url" ;; \
		*) deb_url="https://packages.debian.org$$deb_url" ;; \
	esac; \
	curl -fL "$$deb_url" -o "$$deb"; \
	( cd "$$tmpdir" && ar x busybox-static.deb ); \
	data_archive=$$(find "$$tmpdir" -maxdepth 1 -name 'data.tar.*' -print | head -n 1); \
	if [ -z "$$data_archive" ]; then \
		printf "$(RED)✗ Debian package did not contain data.tar.*$(RESET)\n"; \
		exit 1; \
	fi; \
	mkdir -p "$$tmpdir/root"; \
	tar -xf "$$data_archive" -C "$$tmpdir/root"; \
	if [ ! -x "$$tmpdir/root/usr/bin/busybox" ]; then \
		printf "$(RED)✗ Debian package did not contain /usr/bin/busybox$(RESET)\n"; \
		exit 1; \
	fi; \
	cp "$$tmpdir/root/usr/bin/busybox" "$@"; \
	chmod 0755 "$@"; \
	rm -rf "$$tmpdir"

## Run busybox applet smoke tests
test-busybox: $(ELFUSE_BIN) $(BUSYBOX_DEPS)
	@if [ ! -x "$(BUSYBOX_BIN)" ]; then \
		printf "$(RED)✗ Busybox not found.$(RESET) Set BUSYBOX_BIN=/path/to/busybox.\n"; \
		exit 1; \
	fi
	@bash tests/test-busybox.sh $(ELFUSE_BIN) $(BUSYBOX_BIN)

## Validate ELFUSE_RUNTIME_STATS output shapes (json/jsonl/summary + signal)
test-runtime-stats: $(ELFUSE_BIN) $(BUSYBOX_DEPS)
	@if [ ! -x "$(BUSYBOX_BIN)" ]; then \
		printf "$(RED)✗ Busybox not found.$(RESET) Set BUSYBOX_BIN=/path/to/busybox.\n"; \
		exit 1; \
	fi
	@bash tests/test-runtime-stats.sh $(ELFUSE_BIN) $(BUSYBOX_BIN)

## Run the low-stack argv rewrite regression on busybox startup
test-proctitle-low-stack: $(ELFUSE_BIN) $(BUSYBOX_DEPS)
	@if [ ! -x "$(BUSYBOX_BIN)" ]; then \
		printf "$(RED)✗ Busybox not found.$(RESET) Set BUSYBOX_BIN=/path/to/busybox.\n"; \
		exit 1; \
	fi
	@bash tests/test-proctitle-low-stack.sh $(ELFUSE_BIN) $(BUSYBOX_BIN)

# Static binary integration tests
ifdef GUEST_STATIC_BINS
  ifneq ($(wildcard $(GUEST_STATIC_BINS)/bin),)
    STATIC_BINS_DIR ?= $(GUEST_STATIC_BINS)/bin
  else
    STATIC_BINS_DIR ?= $(GUEST_STATIC_BINS)
  endif
endif

## Run static binary smoke tests (bash, lua, gawk, jq, sqlite, etc.)
test-static-bins: $(ELFUSE_BIN)
	@if [ ! -d "$(STATIC_BINS_DIR)" ]; then \
		printf "$(RED)✗ Static bins not found.$(RESET) Set STATIC_BINS_DIR=/path/to/bin.\n"; \
		exit 1; \
	fi
	@if [ -n "$(SYSROOT_DIR)" ] && [ -d "$(SYSROOT_DIR)" ]; then \
		bash tests/test-static-bins.sh $(ELFUSE_BIN) $(STATIC_BINS_DIR) $(SYSROOT_DIR); \
	else \
		bash tests/test-static-bins.sh $(ELFUSE_BIN) $(STATIC_BINS_DIR); \
	fi

# Dynamic linking tests
# Musl sysroot with dynamic linker + libc.so.
SYSROOT_DIR ?= $(GUEST_SYSROOT)
ifdef GUEST_DYNAMIC_COREUTILS
  ifneq ($(wildcard $(GUEST_DYNAMIC_COREUTILS)/bin),)
    DYNAMIC_COREUTILS_BIN ?= $(GUEST_DYNAMIC_COREUTILS)/bin
  else
    DYNAMIC_COREUTILS_BIN ?= $(GUEST_DYNAMIC_COREUTILS)
  endif
endif

## Run dynamic linking smoke test (hello-dynamic via --sysroot)
test-dynamic: $(ELFUSE_BIN)
	@if [ -z "$(SYSROOT_DIR)" ] || [ ! -d "$(SYSROOT_DIR)" ]; then \
		printf "$(RED)✗ Sysroot not found.$(RESET) Set SYSROOT_DIR=/path/to/sysroot.\n"; \
		exit 1; \
	fi
	@printf "$(BLUE)▸ Running$(RESET) dynamic hello-dynamic (--sysroot)\n"
	$(ELFUSE_BIN) --sysroot $(SYSROOT_DIR) $(GUEST_DYNAMIC_TESTS)/bin/hello-dynamic

## Run guest FUSE validation
# test-fuse-basic is statically linked and accesses exactly one host path:
# /mnt/fuse (open + access). /dev/fuse is intercepted by elfuse internally.
# A minimal sysroot under build/ that contains only /mnt/fuse is therefore
# sufficient coverage; the earlier dependency on the full Alpine fixture
# tree was incidental and broke `make distclean && make check` whenever
# the Alpine CDN pruned a pinned package version.
#
# An explicit SYSROOT_DIR override is still honored for users who want
# the test to run against their own sysroot (e.g. the Alpine fixtures
# fetched separately for the broader matrix runner).
test-fuse-alpine: $(ELFUSE_BIN) $(BUILD_DIR)/test-fuse-basic
	@sysroot="$(SYSROOT_DIR)"; \
	if [ -z "$$sysroot" ] || [ ! -d "$$sysroot" ]; then \
		sysroot="$(BUILD_DIR)/fuse-scratch-sysroot"; \
		mkdir -p "$$sysroot/mnt/fuse"; \
	fi; \
	bash tests/test-fuse-alpine.sh $(ELFUSE_BIN) "$$sysroot" $(BUILD_DIR)/test-fuse-basic

## Run dynamically-linked coreutils tests (--sysroot)
test-dynamic-coreutils: $(ELFUSE_BIN)
	@if [ -z "$(SYSROOT_DIR)" ] || [ ! -d "$(SYSROOT_DIR)" ]; then \
		printf "$(RED)✗ Sysroot not found.$(RESET) Set SYSROOT_DIR=/path/to/sysroot.\n"; \
		exit 1; \
	fi
	@if [ ! -d "$(DYNAMIC_COREUTILS_BIN)" ]; then \
		printf "$(RED)✗ Dynamic coreutils not found.$(RESET) Set DYNAMIC_COREUTILS_BIN=/path/to/bin.\n"; \
		exit 1; \
	fi
	@if [ "$(DYNAMIC_COREUTILS_BIN)" = "$(FIXTURES_DIR)/aarch64-musl/dyn-bin" ]; then \
		COREUTILS_PROFILE=smoke bash tests/test-dynamic-coreutils.sh $(ELFUSE_BIN) $(SYSROOT_DIR) $(DYNAMIC_COREUTILS_BIN); \
	else \
		bash tests/test-dynamic-coreutils.sh $(ELFUSE_BIN) $(SYSROOT_DIR) $(DYNAMIC_COREUTILS_BIN); \
	fi

# glibc dynamic linking tests
# glibc sysroot with dynamic linker + libc.so.
GLIBC_SYSROOT_DIR ?= $(GUEST_GLIBC_SYSROOT)
ifdef GUEST_GLIBC_DYNAMIC_COREUTILS
  ifneq ($(wildcard $(GUEST_GLIBC_DYNAMIC_COREUTILS)/bin),)
    GLIBC_DYNAMIC_COREUTILS_BIN ?= $(GUEST_GLIBC_DYNAMIC_COREUTILS)/bin
  else
    GLIBC_DYNAMIC_COREUTILS_BIN ?= $(GUEST_GLIBC_DYNAMIC_COREUTILS)
  endif
endif

## Run glibc dynamic linking smoke test (hello-dynamic via --sysroot)
test-glibc-dynamic: $(ELFUSE_BIN)
	@if [ -z "$(GLIBC_SYSROOT_DIR)" ] || [ ! -d "$(GLIBC_SYSROOT_DIR)" ]; then \
		printf "$(RED)✗ glibc sysroot not found.$(RESET) Set GLIBC_SYSROOT_DIR=/path/to/sysroot.\n"; \
		exit 1; \
	fi
	@printf "$(BLUE)▸ Running$(RESET) glibc hello-dynamic (--sysroot)\n"
	$(ELFUSE_BIN) --sysroot $(GLIBC_SYSROOT_DIR) $(GUEST_GLIBC_DYNAMIC_TESTS)/bin/hello-dynamic

## Run glibc dynamically-linked coreutils tests (--sysroot)
test-glibc-coreutils: $(ELFUSE_BIN)
	@if [ -z "$(GLIBC_SYSROOT_DIR)" ] || [ ! -d "$(GLIBC_SYSROOT_DIR)" ]; then \
		printf "$(RED)✗ glibc sysroot not found.$(RESET) Set GLIBC_SYSROOT_DIR=/path/to/sysroot.\n"; \
		exit 1; \
	fi
	@if [ ! -d "$(GLIBC_DYNAMIC_COREUTILS_BIN)" ]; then \
		printf "$(RED)✗ glibc dynamic coreutils not found.$(RESET) Set GLIBC_DYNAMIC_COREUTILS_BIN=/path/to/bin.\n"; \
		exit 1; \
	fi
	@SUITE_LABEL="glibc dynamic GNU coreutils test suite (--sysroot)" \
	    SUITE_SUMMARY="glibc results" \
	    bash tests/test-dynamic-coreutils.sh $(ELFUSE_BIN) $(GLIBC_SYSROOT_DIR) $(GLIBC_DYNAMIC_COREUTILS_BIN)

# Performance benchmark
ifneq ($(wildcard $(BUILD_DIR)/busybox),)
  PERF_BIN ?= $(BUILD_DIR)/perf-bin
  PERF_DEPS := $(addprefix $(PERF_BIN)/,grep wc cat sort)
else
  PERF_BIN ?= $(COREUTILS_BIN)
  PERF_DEPS :=
endif

$(BUILD_DIR)/perf-bin:
	@mkdir -p $@

$(BUILD_DIR)/perf-bin/%: $(BUILD_DIR)/busybox | $(BUILD_DIR)/perf-bin
	@ln -sf ../busybox $@

## Run performance benchmarks (native vs elfuse, 10 iterations each)
test-perf: $(ELFUSE_BIN) $(PERF_DEPS)
	@if [ ! -d "$(PERF_BIN)" ]; then \
		printf "$(RED)✗ Perf tools not found.$(RESET) Set COREUTILS_BIN=/path/to/bin or provide $(BUILD_DIR)/busybox.\n"; \
		exit 1; \
	fi
	@bash tests/test-perf.sh $(ELFUSE_BIN) $(PERF_BIN)

## Alias for test-perf
perf: test-perf

# Test matrix (elfuse aarch64 + qemu aarch64 + elfuse x86_64/Rosetta)
## Run full test matrix (all modes: elfuse-aarch64, qemu-aarch64, elfuse-x86_64)
test-matrix: $(ELFUSE_BIN) $(TEST_DEPS)
	@bash tests/test-matrix.sh all

## Run test matrix: elfuse aarch64 mode
test-matrix-elfuse-aarch64: $(ELFUSE_BIN) $(TEST_DEPS)
	@bash tests/test-matrix.sh elfuse-aarch64

## Run test matrix: qemu aarch64 mode
test-matrix-qemu-aarch64: $(ELFUSE_BIN) $(TEST_DEPS)
	@bash tests/test-matrix.sh qemu-aarch64

## Run test matrix: elfuse x86_64-via-Rosetta mode
test-matrix-elfuse-x86_64: $(ELFUSE_BIN) $(TEST_DEPS)
	@bash tests/test-matrix.sh elfuse-x86_64

# Full test suite
## Run the complete test suite (aarch64: unit + busybox + gdbstub + coreutils + static + dynamic)
test-full: $(ELFUSE_BIN)
	@printf "\n$(CYAN)╔══════════════════════════════════════════════════════╗$(RESET)\n"
	@printf "$(CYAN)║              elfuse full test suite                      ║$(RESET)\n"
	@printf "$(CYAN)╚══════════════════════════════════════════════════════╝$(RESET)\n"
	@fail=0; \
	printf "\n$(BLUE)━━━ [1/6] aarch64 unit tests + busybox ━━━$(RESET)\n"; \
	$(MAKE) --no-print-directory check || fail=$$((fail + 1)); \
	printf "\n$(BLUE)━━━ [2/6] GDB stub integration (LLDB) ━━━$(RESET)\n"; \
	$(MAKE) --no-print-directory test-gdbstub || fail=$$((fail + 1)); \
	printf "\n$(BLUE)━━━ [3/6] aarch64 coreutils (static) ━━━$(RESET)\n"; \
	if [ -n "$(COREUTILS_BIN)" ] && [ -d "$(COREUTILS_BIN)" ] && \
	   [ "$(COREUTILS_BIN)" != "$(FIXTURES_DIR)/aarch64-musl/dyn-bin" ]; then \
		$(MAKE) --no-print-directory test-coreutils || fail=$$((fail + 1)); \
	else \
		printf "$(YELLOW)SKIP$(RESET) static coreutils suite (set COREUTILS_BIN to a dedicated full coreutils bundle)\n"; \
	fi; \
	printf "\n$(BLUE)━━━ [4/6] aarch64 static bins (bash, jq, sqlite, lua, ...) ━━━$(RESET)\n"; \
	$(MAKE) --no-print-directory test-static-bins || fail=$$((fail + 1)); \
	printf "\n$(BLUE)━━━ [5/6] aarch64 dynamic coreutils (musl) ━━━$(RESET)\n"; \
	$(MAKE) --no-print-directory test-dynamic-coreutils || fail=$$((fail + 1)); \
	printf "\n$(BLUE)━━━ [6/6] aarch64 dynamic coreutils (glibc) ━━━$(RESET)\n"; \
	if [ -n "$(GLIBC_SYSROOT_DIR)" ] && [ -d "$(GLIBC_SYSROOT_DIR)" ] && \
	   [ -n "$(GLIBC_DYNAMIC_COREUTILS_BIN)" ] && [ -d "$(GLIBC_DYNAMIC_COREUTILS_BIN)" ]; then \
		$(MAKE) --no-print-directory test-glibc-coreutils || fail=$$((fail + 1)); \
	else \
		printf "$(YELLOW)SKIP$(RESET) glibc dynamic coreutils (set GLIBC_SYSROOT_DIR and GLIBC_DYNAMIC_COREUTILS_BIN)\n"; \
	fi; \
	printf "\n$(CYAN)╔══════════════════════════════════════════════════════╗$(RESET)\n"; \
	if [ "$$fail" -eq 0 ]; then \
		printf "$(CYAN)║  $(GREEN)✓ All required suites passed$(CYAN)                      ║$(RESET)\n"; \
	else \
		printf "$(CYAN)║  $(RED)✗ $$fail suite(s) had failures$(CYAN)                        ║$(RESET)\n"; \
	fi; \
	printf "$(CYAN)╚══════════════════════════════════════════════════════╝$(RESET)\n"; \
	[ "$$fail" -eq 0 ]

# Multi-vCPU validation test
# Build rules in top-level Makefile; these are just run targets.

## Run multi-vCPU validation tests (5 tests)
test-multi-vcpu: $(BUILD_DIR)/test-multi-vcpu
	$(BUILD_DIR)/test-multi-vcpu

# RWX page table entry test
## Run RWX page table entry test (does HVF allow W+X?)
test-rwx: $(BUILD_DIR)/test-rwx
	$(BUILD_DIR)/test-rwx

# Fork IPC protocol identity regression
## Run the fork IPC protocol identity unit test
test-fork-ipc-protocol-host: $(BUILD_DIR)/test-fork-ipc-protocol-host
	$(BUILD_DIR)/test-fork-ipc-protocol-host

# Proctitle argv-tail regression
## Run the deterministic argv-tail overshoot guard test
test-proctitle-host: $(BUILD_DIR)/test-proctitle-host
	$(BUILD_DIR)/test-proctitle-host

# Shebang parser unit test
## Run shebang parsing unit tests
test-shebang-host: $(BUILD_DIR)/test-shebang-host
	$(BUILD_DIR)/test-shebang-host
