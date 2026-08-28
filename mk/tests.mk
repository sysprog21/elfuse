# Test targets

# Keep the mremap descriptor-exhaustion regression at elfuse's documented host
# minimum. The guest probe consumes the remaining host reserve after startup
# and verifies that its filler failure is descriptor-driven. The manifest
# annotation, Make recipe, and shell runners all derive this value from
# src/elfuse-limits.h.
ELFUSE_HOST_NOFILE_MIN ?= $(shell bash "$(CURDIR)/tests/test-config.sh" --host-nofile)

.PHONY: test-hello test-all check check-syscall-coverage check-eintr-contract check-lock-order check-atomics check-skill-refs test-gdbstub test-coreutils test-busybox \
        test-static-bins \
        test-dynamic test-dynamic-coreutils test-glibc-dynamic \
        test-glibc-coreutils test-perf \
        test-rosetta-cli test-rosetta-statics test-rosetta-failure-modes \
        test-rosetta-alpine test-rosetta-audit test-rosetta-jit \
        test-rosetta-glibc test-rosetta-madvise test-rosetta-msync \
        test-rosetta-mremap test-rosetta-all test-sharun bench-rosetta \
        test-matrix test-matrix-elfuse-aarch64 test-matrix-qemu-aarch64 \
        test-full test-multi-vcpu test-rwx test-sysroot-rename \
        test-case-collision test-case-collision-fallback test-getdents64-overlong \
        test-sysroot-tmp-remove test-sysroot-host-fallback test-sysroot-case-exact \
        test-sysroot-create-paths test-fork-ipc-protocol-host \
        test-vcpu-run-hooks-host test-identity-override-host \
        test-dynamic-array-host test-string-builder-host \
        test-config \
        test-mremap-tail-emfile \
        test-proctitle-host test-proctitle-low-stack \
        test-sysroot-procfs-exec test-sysroot-fd-magiclink \
        test-timeout-disable test-launch-flags \
        test-fuse-alpine \
        test-sysroot-nofollow test-sysroot-chdir test-sysroot-symlink-escape \
        test-sysroot-dotdot test-sysroot-openat2-walk \
        test-sysroot-inotify-names test-sysroot-exec-names \
        test-sysroot-interp-fallback test-sysroot-interp-cased \
        test-sysroot-absock-names test-absock-cleanup \
        test-linkat-symlink-fallback test-casefold-host \
        test-casefold-walk-host test-absock-names-host \
        test-wakeup-pipe-host test-guest-env-host \
        test-sysroot-name-unique \
        test-sysroot-name-relative \
        test-nosysroot-literal-names test-sysroot-outside-names \
        test-sysroot-root \
        test-sysroot-symlink-target \
        test-sysroot-name-i18n test-sysroot-name-length \
        test-sysroot-name-staged test-sysroot-name-race \
        test-sysroot-pathmax test-sysroot-corpus \
        test-sysroot-name-soak check-soak \
        check-name-caseexact test-sysroot-path-matrix \
        test-usage-synopsis \
        probe-volume-naming perf

## Build and run the assembly hello world test
test-hello: $(ELFUSE_BIN) $(TEST_HELLO_DEP)
	@printf "$(BLUE)▸ Running$(RESET) test-hello\n"
	$(ELFUSE_BIN) $(TEST_DIR)/test-hello

## Verify test-config.sh keeps its CLI mode separate from sourced mode
test-config:
	@bash tests/test-config-cli.sh

## Run the libc-based file-backed region removal EMFILE regression probe
test-mremap-tail-emfile: $(ELFUSE_BIN) $(BUILD_DIR)/test-mremap-tail-emfile
	@printf "$(BLUE)▸ Running$(RESET) test-mremap-tail-emfile\n"
	(ulimit -n $(ELFUSE_HOST_NOFILE_MIN) && \
		$(ELFUSE_BIN) $(BUILD_DIR)/test-mremap-tail-emfile)

## Verify dispatch.tbl coverage of the kernel-supported syscall set
check-syscall-coverage:
	@python3 scripts/check-syscall-coverage.py

## Verify every path that can report EINTR states whether it may be restarted
check-eintr-contract:
	@python3 scripts/check-eintr-contract.py

## Verify every lock in the tree is named by the lock-order document
check-lock-order:
	@python3 scripts/check-lock-order.py --self-test
	@python3 scripts/check-lock-order.py

## Fail when an atomic access states no memory order
check-atomics:
	@echo "  ATOMICS src/"
	@python3 scripts/check-atomics.py --self-test
	@python3 scripts/check-atomics.py

## Verify every path, target, and section the skills name still resolves
check-skill-refs:
	@python3 scripts/check-skill-refs.py --self-test
	@python3 scripts/check-skill-refs.py

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

.PHONY: check-asan check-ubsan check-tsan check-sanitizer

# Sanitizer builds target elfuse's own internals, not Linux syscall
# compatibility -- the release lane already covers that via test-matrix. So the
# check-{asan,ubsan,tsan} entry points run check-sanitizer, a representative
# subset of manifest sections that stress concurrency, memory, fork, and signal
# machinery (where ASAN/UBSAN/TSAN actually find bugs) instead of the full
# check suite.
#
# Sanitized guests run several times slower, so widen the per-test timeout
# (test-runner.sh defaults to 10s) to keep the slowdown from surfacing as a
# spurious TIMEOUT. TEST_TIMEOUT is only overridden if the caller has not
# already set one.

# No "clean" prerequisite. These lanes used to depend on it, which removed the
# whole build tree including the 186 cross-compiled guest binaries -- built with
# CROSS_TEST_CFLAGS, and so untouched by anything EXTRA_CFLAGS says. The FLAVOR
# stamp in mk/common.mk was added later to solve the same problem exactly:
# it removes the *.o and *.d that a CFLAGS change actually invalidates, and
# leaves the rest. Measured on this tree, the clean cost 186 needless
# cross-compiles per sanitizer run, most of the lane's wall time.
#
# What still protects the link is the stamp, not the clean: the sub-make below
# re-reads common.mk with the sanitizer CFLAGS, sees a different flavor, and
# drops every host object before anything is compiled or linked.

## Run the sanitizer subset with AddressSanitizer (ASAN)
check-asan:
	ASAN_OPTIONS="abort_on_error=1:detect_leaks=0" TEST_TIMEOUT="$${TEST_TIMEOUT:-30}" $(MAKE) EXTRA_CFLAGS="-fsanitize=address -fno-omit-frame-pointer" check-sanitizer

## Run the sanitizer subset with UndefinedBehaviorSanitizer (UBSAN)
check-ubsan:
	UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" TEST_TIMEOUT="$${TEST_TIMEOUT:-30}" $(MAKE) EXTRA_CFLAGS="-fsanitize=undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer" check-sanitizer

## Run the sanitizer subset with ThreadSanitizer (TSAN)
check-tsan:
	TSAN_OPTIONS="halt_on_error=1" TEST_TIMEOUT="$${TEST_TIMEOUT:-60}" $(MAKE) EXTRA_CFLAGS="-fsanitize=thread -fno-omit-frame-pointer" check-sanitizer

# Manifest sections that exercise elfuse-internal concurrency, memory, fork,
# and signal machinery -- the highest-signal targets for ASAN/UBSAN/TSAN.
# Selected by tests/driver.sh -s; see tests/manifest.txt for the full list.
# Kept deliberately tight so a TSAN leg (~5s per guest spawn) stays inside the
# CI budget. "I/O subsystem" is included for its fd-table refcount/ABA races
# (epoll-mt/aba/refcount, getdents-refcount) now that fd_entry_t.type is atomic;
# the remaining compat sections (rseq, /proc, sockets) stay on the release lane.
SANITIZER_SECTIONS := Threading|Stress|Signal.*thread|Fork edge|CoW fork|Guard page|mremap|MAP_SHARED|madvise|futex|FD table race|Multithreaded|SysV shared|membarrier|I/O subsystem

# One banner-plus-run pair, for a host unit binary run directly and for a
# lane reached through its own make target. Canned recipes (make manual 5.8)
# rather than 59 hand-kept printf/invoke pairs, so a lane list edit cannot
# leave a banner naming the wrong lane. Banner text arrives through $(call),
# so a comma in it silently splits into $(3) and truncates the banner.
define run-host-unit
@printf "\n$(BLUE)━━━ $(2) ━━━$(RESET)\n"
@$(BUILD_DIR)/$(1)
endef

# The lane is a single '+'-marked recipe line. The '+' is needed because make
# decides what still runs under -n by looking for a literal $(MAKE) in the
# unexpanded recipe line, which a canned recipe hides (make manual 9.3);
# without it, "make -n check" prints the sub-make instead of expanding the
# lane it would run. One line rather than a banner-then-invoke pair because
# once a '+' line appears in an expansion, every later line of that same
# expansion also runs for real under -n, so split banners would behave
# unlike each other, and a non-lane line appended after a run-lane call
# would execute during a dry build.
define run-lane
+@printf "\n$(BLUE)━━━ $(2) ━━━$(RESET)\n"; \
$(MAKE) --no-print-directory $(1)
endef

# Open a lane recipe with a scratch directory in $$tmpdir, removed however
# the recipe exits. Recipes that clean up more than the scratch directory
# replace the trap once the extra paths are named.
define SYSROOT_SCRATCH
set -e; \
tmpdir=$$(mktemp -d); \
trap 'rm -rf "$$tmpdir"' EXIT
endef

# Count the absock namespace dirs before the lane runs, then require the
# count not to have grown: the exit sweeps must leave nothing behind, and a
# grown count is a leaked /tmp/elfuse-absock-<nsid> no later process owns.
define ABSOCK_LEAK_BEFORE
before=$$(ls -d /tmp/elfuse-absock-* 2>/dev/null | wc -l | tr -d ' ')
endef

define ASSERT_NO_ABSOCK_LEAK
after=$$(ls -d /tmp/elfuse-absock-* 2>/dev/null | wc -l | tr -d ' '); \
if [ "$$after" -gt "$$before" ]; then \
	printf "$(RED)FAIL$(RESET) absock namespace dir leaked ($$before -> $$after)\n"; \
	exit 1; \
fi
endef

# The host unit binaries both suites run directly, as prerequisites.
CHECK_HOST_UNIT_BINS := $(addprefix $(BUILD_DIR)/, \
        test-tlbi-encoder-host test-fork-ipc-protocol-host \
        test-vcpu-run-hooks-host test-identity-override-host \
        test-teardown-live-vcpu-host test-stdio-nonblock-host test-casefold-host \
        test-casefold-walk-host test-absock-names-host \
        test-dynamic-array-host test-string-builder-host \
        test-wakeup-pipe-host test-guest-env-host)

# Lanes shared by check and check-sanitizer, in execution order: the host
# unit binaries, then the name-contract lanes cheap enough for a sanitizer
# build. check-sanitizer's coverage is exactly this prefix, kept as one
# explicit sequence rather than "whatever check happens to run".
define CHECK_SHARED_LANES
$(call run-host-unit,test-tlbi-encoder-host,TLBI RVAE1IS encoder unit test)
$(call run-host-unit,test-fork-ipc-protocol-host,fork IPC protocol identity unit test)
$(call run-host-unit,test-vcpu-run-hooks-host,vCPU run-loop hook API unit test)
$(call run-host-unit,test-identity-override-host,identity override unit test)
$(call run-host-unit,test-teardown-live-vcpu-host,teardown live-worker accounting unit test)
$(call run-host-unit,test-casefold-host,filename codec unit test)
$(call run-host-unit,test-casefold-walk-host,case-exact path resolution unit test)
$(call run-host-unit,test-absock-names-host,absock derived-name unit test)
$(call run-host-unit,test-dynamic-array-host,dynamic array unit test)
$(call run-host-unit,test-string-builder-host,string builder unit test)
$(call run-host-unit,test-wakeup-pipe-host,wakeup pipe concurrency unit test)
$(call run-host-unit,test-stdio-nonblock-host,launcher stdio flags across a guest)
$(call run-host-unit,test-guest-env-host,guest environment merge cross product)
$(call run-lane,test-sysroot-name-unique,one on-disk name per guest name)
$(call run-lane,test-sysroot-name-relative,relative and dirfd-relative names)
$(call run-lane,test-sysroot-name-i18n,non-ASCII guest filenames)
$(call run-lane,test-sysroot-name-length,guest filenames at full length)
$(call run-lane,test-sysroot-name-staged,host-staged escape-shaped names)
endef

## Run the representative internal-implementation subset (for sanitizer builds)
check-sanitizer: $(ELFUSE_BIN) $(TEST_DEPS) $(CHECK_HOST_UNIT_BINS)
	@bash tests/driver.sh -e $(ELFUSE_BIN) -d $(TEST_DIR) -v -s '$(SANITIZER_SECTIONS)'
	$(CHECK_SHARED_LANES)

## Run the unit test suite plus busybox applet validation
check: $(ELFUSE_BIN) $(TEST_DEPS) check-syscall-coverage check-eintr-contract check-lock-order check-atomics check-skill-refs test-config \
		$(CHECK_HOST_UNIT_BINS)
	@bash tests/driver.sh -e $(ELFUSE_BIN) -d $(TEST_DIR) -v
	$(CHECK_SHARED_LANES)
	$(call run-lane,test-sysroot-name-race,concurrent creation of colliding names)
	$(call run-lane,test-sysroot-pathmax,guest paths at the host path ceiling)
	$(call run-lane,test-sysroot-corpus,frozen on-disk spelling corpus)
	$(call run-lane,test-sysroot-path-matrix,addressing modes agree across the path matrix)
	$(call run-lane,test-usage-synopsis,usage synopsis renderings)
	$(call run-lane,test-shebang-host,shebang parser unit test)
	$(call run-lane,test-gva-contracts,proved/gva.h call-site contract checks)
	$(call run-lane,test-proctitle-host,proctitle argv-tail regression)
	$(call run-lane,test-proctitle-low-stack,proctitle low-stack regression)
	$(call run-lane,test-busybox,busybox applet validation)
	$(call run-lane,test-sysroot-procfs-exec,sysroot procfs exec validation)
	$(call run-lane,test-sysroot-fd-magiclink,fd magic link resolution)
	$(call run-lane,test-getdents64-overlong,getdents64 overlong-UTF-8 dirent skip)
	$(call run-lane,test-sysroot-host-fallback,sysroot host-fallback validation)
	$(call run-lane,test-sysroot-tmp-remove,sysroot /tmp remove/rename consistency)
	$(call run-lane,test-sysroot-case-exact,sysroot byte-exact lookup validation)
	$(call run-lane,test-sysroot-symlink-escape,sysroot relative-dirfd symlink escape validation)
	$(call run-lane,test-sysroot-openat2-walk,no-symlinks path walking)
	$(call run-lane,test-sysroot-dotdot,sysroot '..' resolution)
	$(call run-lane,test-sysroot-symlink-target,escaped symlink-target resolution)
	$(call run-lane,test-sysroot-inotify-names,inotify names across the escape boundary)
	$(call run-lane,test-sysroot-exec-names,exec identity across the escape boundary)
	$(call run-lane,test-sysroot-interp-fallback,PT_INTERP /lib fallback)
	$(call run-lane,test-sysroot-interp-cased,PT_INTERP through an escaped path)
	$(call run-lane,test-sysroot-absock-names,pathname sockets across the escape boundary)
	$(call run-lane,test-absock-cleanup,absock namespace lifecycle)
	$(call run-lane,test-sysroot-root,sysroot mounted at /)
	$(call run-lane,test-nosysroot-literal-names,literal names without a sysroot)
	$(call run-lane,test-sysroot-outside-names,literal names outside the sysroot)
	$(call run-lane,test-sysroot-chdir,guest-visible working directory)
	$(call run-lane,test-case-collision-fallback,case collisions on a folding sysroot)
	$(call run-lane,test-fuse-alpine,Alpine sysroot FUSE validation)
	$(call run-lane,test-timeout-disable,timeout=0 validation)
	$(call run-lane,test-launch-flags,launch flags)
	$(call run-lane,test-rosetta-cli,rosetta CLI gating)
	$(call run-lane,test-bench-guardrail,hot-syscall guardrail)
	$(call run-lane,test-sharun,sharun launcher and probe)
	$(call run-lane,test-conformance-harness,conformance harness selftests)

## Hot-syscall performance guardrail: ensure getpid, libc clock_gettime,
## and 1-byte /dev/urandom reads stay under their TODO ns/op ceilings.
## Builds the dynamic-glibc variant opportunistically; the script skips
## that arm when the cross-toolchain sysroot is missing.
BENCH_GUARDRAIL_DEPS := $(ELFUSE_BIN)
BENCH_GUARDRAIL_REQUIRE_STATIC := 0
ifndef GUEST_TEST_BINARIES
  BENCH_GUARDRAIL_DEPS += $(BUILD_DIR)/bench-hot-guard
  BENCH_GUARDRAIL_REQUIRE_STATIC := 1
  ifneq ($(CROSS_GLIBC_SYSROOT_PRESENT),)
    BENCH_GUARDRAIL_DEPS += $(BUILD_DIR)/bench-hot-guard-glibc
  endif
endif
test-bench-guardrail: $(BENCH_GUARDRAIL_DEPS)
	@ELFUSE="$(ELFUSE_BIN)" \
	    BENCH_GUARDRAIL_DIR="$(TEST_DIR)" \
	    BENCH_GUARDRAIL_REQUIRE_STATIC="$(BENCH_GUARDRAIL_REQUIRE_STATIC)" \
	    LINUX_TOOLCHAIN="$(LINUX_TOOLCHAIN)" \
	    GLIBC_SYSROOT="$(CROSS_GLIBC_SYSROOT)" \
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

## openat2(RESOLVE_NO_SYMLINKS) is answered by a manual walk over the host
## spelling, so a link-free path must resolve however deep it runs and however
## many directories the sysroot itself adds in front of it. The chains are
## staged host-side so their names reach the disk literally. mktemp places the
## sysroot several directories down, which is what makes the shallow chain
## cross the link budget once the prefix is counted.
test-sysroot-openat2-walk: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-openat2-walk
	@set -e; \
	tmpdir=$$(mktemp -d); \
	sysroot="$$tmpdir/sysroot"; \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	for spec in "deep 44" "shallow 38"; do \
		set -- $$spec; \
		chain="$$sysroot/$$1"; \
		i=0; \
		while [ "$$i" -lt "$$2" ]; do chain="$$chain/d"; i=$$((i + 1)); done; \
		mkdir -p "$$chain"; \
	done; \
	mkdir -p "$$sysroot/real/leaf"; \
	mkdir -p "$$sysroot/tmp/leaf"; \
	ln -sf real "$$sysroot/link"; \
	$(ELFUSE_BIN) --sysroot "$$sysroot" $(BUILD_DIR)/test-sysroot-openat2-walk

## Linux clamps '..' at the root a process resolves from, so the directory
## holding the sysroot is not reachable from inside it. beside.txt is staged
## there as a real escape target, and the post-run checks confirm the guest's
## own creates landed in the sysroot rather than beside it.
test-sysroot-dotdot: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-dotdot
	@set -e; \
	tmpdir=$$(mktemp -d); \
	sysroot="$$tmpdir/sysroot"; \
	beside="$$tmpdir/beside.txt"; \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	mkdir -p "$$sysroot/tmp"; \
	printf 'guest-probe\n' > "$$sysroot/probe.txt"; \
	printf 'HOST-SIDE-FILE\n' > "$$beside"; \
	$(ELFUSE_BIN) --sysroot "$$sysroot" $(BUILD_DIR)/test-sysroot-dotdot; \
	if [ -e "$$tmpdir/made-here.txt" ] || [ -e "$$tmpdir/made-dir" ] || \
			[ -e "$$tmpdir/var" ]; then \
		printf "$(RED)FAIL$(RESET) a create through /.. escaped the sysroot\n"; \
		exit 1; \
	fi

## A symlink reachable through a sysroot-contained dirfd must not escape via
## openat(dirfd, name): stages both an absolute-target and a deep-".."
## relative-target symlink under $sysroot/d1, each pointing at a secret file
## in a second tmpdir well outside the sysroot.
test-sysroot-symlink-escape: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-symlink-escape
	@set -e; \
	tmpdir=$$(mktemp -d); \
	secret_dir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir" "$$secret_dir"' EXIT; \
	mkdir -p "$$tmpdir/d1" "$$tmpdir/d2"; \
	printf 'inside-sysroot\n' > "$$tmpdir/d1/normal.txt"; \
	printf 'SECRET-HOST-FILE\n' > "$$secret_dir/secret.txt"; \
	ln -sf "$$secret_dir/secret.txt" "$$tmpdir/d1/abs-link"; \
	ln -sf "$$secret_dir/secret.txt" "$$tmpdir/d2/abs-link"; \
	ln -sf "../d2/abs-link" "$$tmpdir/d1/chain-link"; \
	depth=$$(printf '%s' "$$tmpdir/d1" | tr -cd '/' | wc -c | tr -d ' '); \
	relback=""; i=0; \
	while [ "$$i" -lt "$$depth" ]; do relback="../$$relback"; i=$$((i + 1)); done; \
	ln -sf "$${relback}$${secret_dir#/}/secret.txt" "$$tmpdir/d1/rel-link"; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-sysroot-symlink-escape

## sys_linkat() falls back to symlinkat() when the host linkat() rejects a
## hard link to a symlink source. APFS accepts that call directly and would
## never exercise the fallback, so this builds a scratch Case-sensitive HFS+
## disk image via hdiutil (same tool sysroot.c uses for --create-sysroot
## sparsebundles) and uses it as --sysroot. Not wired into `check`: like
## test-case-collision, disk-image creation is heavier than the plain-tmpdir
## sysroot tests above, so this stays a standalone, manually-run target.
## Skips (exit 0) when hdiutil/HFS+ is unavailable, or when this particular
## volume happens to allow linkat-to-symlink directly and so cannot exercise
## the fallback.
test-linkat-symlink-fallback: $(ELFUSE_BIN) $(BUILD_DIR)/test-linkat-symlink-fallback
	@dmg=$$(mktemp -u).dmg; mnt=""; \
	trap '[ -n "$$mnt" ] && hdiutil detach "$$mnt" -quiet >/dev/null 2>&1; rm -f "$$dmg"' EXIT; \
	if ! hdiutil create -size 16m -fs "Case-sensitive HFS+" \
	        -volname elfuselinkfb -quiet "$$dmg" >/dev/null 2>&1; then \
		printf "$(YELLOW)SKIP$(RESET) test-linkat-symlink-fallback (hdiutil create failed)\n"; \
		exit 0; \
	fi; \
	mnt=$$(hdiutil attach "$$dmg" -nobrowse | awk '/\/Volumes\//{print $$NF}'); \
	if [ -z "$$mnt" ]; then \
		printf "$(YELLOW)SKIP$(RESET) test-linkat-symlink-fallback (hdiutil attach failed)\n"; \
		exit 0; \
	fi; \
	sysroot="$$mnt/sysroot"; \
	mkdir -p "$$sysroot/d1"; \
	printf 'hello\n' > "$$sysroot/d1/target.txt"; \
	ln -s target.txt "$$sysroot/d1/sym"; \
	if ln -P "$$sysroot/d1/sym" "$$sysroot/d1/probe" 2>/dev/null; then \
		rm -f "$$sysroot/d1/probe"; \
		printf "$(YELLOW)SKIP$(RESET) test-linkat-symlink-fallback (volume allows linkat-to-symlink directly; fallback not exercised)\n"; \
		exit 0; \
	fi; \
	$(ELFUSE_BIN) --sysroot "$$sysroot" $(BUILD_DIR)/test-linkat-symlink-fallback

test-case-collision: $(ELFUSE_BIN) $(BUILD_DIR)/test-case-collision
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	$(ELFUSE_BIN) --create-sysroot "$$tmpdir/case-sysroot" $(BUILD_DIR)/test-case-collision

test-case-collision-fallback: $(ELFUSE_BIN) $(BUILD_DIR)/test-case-collision
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-case-collision

## Host paths outside the sysroot must stay reachable when the sysroot is
## case-insensitive (case-exact walk active): the walk defers to the
## resolver's host-literal fallback instead of vetoing it with ENOENT.
## Regression test for the test-matrix "musl dyn" coreutils failures.
test-sysroot-host-fallback: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-host-fallback
	@$(SYSROOT_SCRATCH); \
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
	mkdir -p "$$sysroot/etc"; \
	printf 'guest-passwd\n' > "$$sysroot/etc/passwd"; \
	$(ELFUSE_BIN) --sysroot "$$sysroot" \
	    $(BUILD_DIR)/test-sysroot-host-fallback \
	    "$$hostdir" "$$mirror/final.txt" "$$mirror/both.txt"

## Stages a directory under the runner's own /tmp, the one prefix the guest
## addresses through the redirect rather than through the host-literal fallback,
## so a guest that still reached the host would see entries it cannot remove.
## The sysroot itself comes from TMPDIR (/var/folders on macOS), which is not
## redirected, so the harness can inspect where the guest's own writes landed.
## Placement is asserted without spelling any name under the sysroot: on a
## case-insensitive volume the name codec may store any component under an
## escaped spelling, so the harness checks only that the redirect populated the
## sysroot's /tmp at all. The guest side proves the file itself by reading it
## back.
## Verify guest /tmp resolves through the sysroot for lookups as well as creates
test-sysroot-tmp-remove: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-tmp-remove
	@set -e; \
	tmpdir=$$(mktemp -d); \
	hostdir=$$(mktemp -d /tmp/elfuse-tmp-remove.XXXXXX); \
	trap 'rm -rf "$$tmpdir" "$$hostdir"' EXIT; \
	sysroot="$$tmpdir/sysroot"; \
	mkdir -p "$$sysroot" "$$hostdir/d"; \
	printf 'x' > "$$hostdir/f"; \
	printf 'x' > "$$hostdir/r"; \
	$(ELFUSE_BIN) --sysroot "$$sysroot" \
	    $(BUILD_DIR)/test-sysroot-tmp-remove "$$hostdir"; \
	if [ "$$(ls -A "$$hostdir" | sort | tr '\n' ' ')" != "d f r " ]; then \
		printf "$(RED)FAIL$(RESET) guest reached the host /tmp staging dir\n"; \
		exit 1; \
	fi; \
	if [ ! -d "$$sysroot/tmp" ] || [ -z "$$(ls -A "$$sysroot/tmp")" ]; then \
		printf "$(RED)FAIL$(RESET) guest /tmp write did not land in the sysroot\n"; \
		exit 1; \
	fi

## Wrong-case (and wrong-normalization) lookups must fail with ENOENT:
## Linux treats names as byte strings, while APFS resolves them case- and
## normalization-insensitively. The case-exact walk verifies the on-disk
## spelling of every fold-stable component instead of trusting the folded
## probe. Stages exact-case fixtures host-side; the guest asserts folded
## spellings do not resolve. The normalization probes require the walk,
## so the guest skips them when the staging volume is case-sensitive.
test-sysroot-case-exact: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-case-exact
	@$(SYSROOT_SCRATCH); \
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

# A guest name whose spelling the volume cannot hold is stored escaped, so a
# directory can hold a mixture of literal and escaped entries. Each guest name
# must stay reachable through exactly one of them, and the on-disk spellings
# must never surface. The recipe asserts the host-side half afterwards: an
# escaped entry whose decoded name is also present literally would be a name
# reachable two ways, and a leftover entry would be one the teardown could not
# name.
## Each guest name has exactly one on-disk representation
test-sysroot-name-unique: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-name-unique
	@$(SYSROOT_SCRATCH); \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" \
	    $(BUILD_DIR)/test-sysroot-name-unique; \
	left=$$(ls -A "$$tmpdir/name-unique" 2>/dev/null | wc -l | tr -d ' '); \
	if [ "$$left" != 0 ]; then \
		printf "$(RED)FAIL$(RESET) %s entries survived the teardown\n" "$$left"; \
		ls -Ab "$$tmpdir/name-unique"; \
		exit 1; \
	fi

# A guest names one file two ways: absolutely, and relative to its working
# directory or a directory descriptor. Both have to reach it, which is not
# automatic when the name is stored under an escaped spelling: a relative name
# has no leading component to key the sysroot resolvers on, only the descriptor
# it is measured against. Tree walkers reach every name this way.
## Relative and dirfd-relative names resolve to the same file as absolute ones
test-sysroot-name-relative: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-name-relative
	@$(SYSROOT_SCRATCH); \
	outside="$$tmpdir-outside"; \
	mkdir -p "$$outside"; \
	trap 'rm -rf "$$tmpdir" "$$tmpdir-outside"' EXIT; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" \
	    $(BUILD_DIR)/test-sysroot-name-relative "$$outside"; \
	stray=$$(ls -A "$$tmpdir/name-relative" \
	    | grep -v '^\.ef=' | grep -cvE '^(walkdir|slashfile|notdirfile)$$' || true); \
	if [ "$$stray" != 0 ]; then \
		printf "$(RED)FAIL$(RESET) %s name(s) stored unescaped\n" "$$stray"; \
		ls -Ab "$$tmpdir/name-relative"; \
		exit 1; \
	fi; \
	if [ ! -d "$$tmpdir/name-relative/walkdir" ] || \
	   [ ! -f "$$tmpdir/name-relative/slashfile" ] || \
	   [ ! -f "$$tmpdir/name-relative/notdirfile" ]; then \
		printf "$(RED)FAIL$(RESET) a fold-stable fixture was escaped\n"; \
		ls -Ab "$$tmpdir/name-relative"; \
		exit 1; \
	fi; \
	if [ ! -e "$$outside/Outside.Rel" ] || [ ! -e "$$outside/Outside.Abs" ]; then \
		printf "$(RED)FAIL$(RESET) a name outside the sysroot was not stored literally\n"; \
		ls -Ab "$$outside"; \
		exit 1; \
	fi

## Symlink targets are resolved in the guest namespace, not the host's
test-sysroot-symlink-target: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-symlink-target
	@$(SYSROOT_SCRATCH); \
	mkdir -p "$$tmpdir/host-downloads"; \
	ln -s "$$HOME" "$$tmpdir/host-home-link"; \
	mkdir -p "$$tmpdir/home/muplar"; \
	ln -s "$$tmpdir/host-downloads" "$$tmpdir/home/muplar/Download"; \
	had_target=0; [ -e "/symlink-target" ] && had_target=1; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" \
	    $(BUILD_DIR)/test-sysroot-symlink-target; \
	if [ "$$had_target" = 0 ] && [ -e "/symlink-target" ]; then \
		printf "$(RED)FAIL$(RESET) a create through a link escaped to the host root\n"; \
		exit 1; \
	fi; \
	if [ -z "$$(find "$$tmpdir" -maxdepth 2 -name '.ef=*' -print -quit)" ]; then \
		printf "$(RED)FAIL$(RESET) no escaped entries in the sysroot\n"; \
		ls -Rb "$$tmpdir"; \
		exit 1; \
	fi

# A pathname socket's address is a filesystem path and resolves like one.
# The recipe asserts the host-side half: the socket the guest leaves bound
# sits inside the sysroot only under its escape, nothing landed at the
# host-literal spelling, and the private shortening-link dir is swept on
# exit.
## pathname AF_UNIX socket addresses resolve through the sysroot
test-sysroot-absock-names: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-absock-names
	@$(SYSROOT_SCRATCH); \
	$(ABSOCK_LEAK_BEFORE); \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" \
	    $(BUILD_DIR)/test-sysroot-absock-names; \
	for leaf in My.Sock Recv.Sock Sender.Sock sock Sock; do \
		if [ -e "/sockdir/$$leaf" ]; then \
			printf "$(RED)FAIL$(RESET) socket path /sockdir/%s escaped to the host root\n" "$$leaf"; \
			exit 1; \
		fi; \
	done; \
	if ls -A "$$tmpdir/sockdir" | grep -qx 'Sock'; then \
		printf "$(RED)FAIL$(RESET) Sock was stored literally\n"; \
		ls -Ab "$$tmpdir/sockdir"; \
		exit 1; \
	fi; \
	$(ASSERT_NO_ABSOCK_LEAK)

# The absock namespace dir is shared across a forked guest tree, so neither
# exit order may destroy state the other side still needs; the recipe also
# asserts the dir itself does not leak.
## absock namespace lifecycle across fork and exit order
test-absock-cleanup: $(ELFUSE_BIN) $(BUILD_DIR)/test-absock-cleanup
	@$(SYSROOT_SCRATCH); \
	$(ABSOCK_LEAK_BEFORE); \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-absock-cleanup; \
	printf "  %-30s " "owner sweep spares live child"; \
	out=$$($(ELFUSE_BIN) --sysroot "$$tmpdir" \
	    $(BUILD_DIR)/test-absock-cleanup owner-sweep 2>/dev/null); \
	verdict=$$(printf '%s\n' "$$out" | sed -n 's/^OWNER_SWEEP=//p'); \
	if [ "$$verdict" = ok ]; then \
		printf "OK\n"; \
	else \
		printf "FAIL: child socket %s\n" "$${verdict:-unreported}"; \
		exit 1; \
	fi; \
	printf "  %-30s " "child mints after owner exit"; \
	out=$$($(ELFUSE_BIN) --sysroot "$$tmpdir" \
	    $(BUILD_DIR)/test-absock-cleanup child-after-owner 2>/dev/null); \
	verdict=$$(printf '%s\n' "$$out" | sed -n 's/^CHILD_AFTER=//p'); \
	if [ "$$verdict" = ok ]; then \
		printf "OK\n"; \
	else \
		printf "FAIL: late bind %s\n" "$${verdict:-unreported}"; \
		exit 1; \
	fi; \
	$(ASSERT_NO_ABSOCK_LEAK)

# PT_INTERP names the loader by the guest's spelling, and a rootfs may ship
# it somewhere other than where the binary asks (store-style paths). The
# interp resolver falls back to /lib/<basename> when the asked-for path does
# not resolve; this pins the fallback with an absent /nix-style prefix.
## PT_INTERP falls back to /lib/<basename> for an absent store path
test-sysroot-interp-fallback: $(ELFUSE_BIN)
	@if [ -z "$(SYSROOT_DIR)" ] || \
	    [ ! -f "$(SYSROOT_DIR)/lib/ld-musl-aarch64.so.1" ] || \
	    [ ! -f "$(DYNAMIC_COREUTILS_BIN)/echo" ]; then \
		printf "$(YELLOW)SKIP$(RESET) test-sysroot-interp-fallback (musl fixtures missing)\n"; \
		exit 0; \
	fi; \
	set -e; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	cp "$(DYNAMIC_COREUTILS_BIN)/echo" "$$tmpdir/echo"; \
	off=$$(grep -abo '/lib/ld-musl-aarch64.so.1' "$$tmpdir/echo" | head -1 | cut -d: -f1); \
	[ -n "$$off" ]; \
	printf '/nix' | dd of="$$tmpdir/echo" bs=1 seek="$$off" conv=notrunc 2>/dev/null; \
	out=$$($(ELFUSE_BIN) --sysroot $(SYSROOT_DIR) "$$tmpdir/echo" interp-fallback-ok); \
	[ "$$out" = "interp-fallback-ok" ]

# The loader itself may live under a case-protected path: the guest stages a
# copy of the musl loader below /NiX (stored escaped), and the patched binary
# asks for it by that spelling with a basename /lib does not carry, so only
# a resolution that walks the escape can launch it, and the /lib fallback
# cannot mask a regression. The exec goes through a guest trampoline because
# the initial process is loaded by the core bootstrap, which resolves
# PT_INTERP by literal concatenation plus the /lib fallback only.
## PT_INTERP resolves through an escaped path
test-sysroot-interp-cased: $(ELFUSE_BIN) $(BUILD_DIR)/mkdir-arg \
		$(BUILD_DIR)/copy-arg $(BUILD_DIR)/exec-arg
	@if [ -z "$(SYSROOT_DIR)" ] || \
	    [ ! -f "$(SYSROOT_DIR)/lib/ld-musl-aarch64.so.1" ] || \
	    [ ! -f "$(DYNAMIC_COREUTILS_BIN)/echo" ]; then \
		printf "$(YELLOW)SKIP$(RESET) test-sysroot-interp-cased (musl fixtures missing)\n"; \
		exit 0; \
	fi; \
	set -e; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	sysroot="$$tmpdir/sysroot"; \
	cp -R "$(SYSROOT_DIR)" "$$sysroot"; \
	mkdir -p "$$sysroot/bin"; \
	cp $(BUILD_DIR)/mkdir-arg "$$sysroot/bin/mkdir-arg"; \
	cp $(BUILD_DIR)/copy-arg "$$sysroot/bin/copy-arg"; \
	cp $(BUILD_DIR)/exec-arg "$$sysroot/bin/exec-arg"; \
	$(ELFUSE_BIN) --sysroot "$$sysroot" "$$sysroot/bin/mkdir-arg" /NiX; \
	$(ELFUSE_BIN) --sysroot "$$sysroot" "$$sysroot/bin/copy-arg" \
	    /lib/ld-musl-aarch64.so.1 /NiX/xd-musl-aarch64.so.1; \
	cp "$(DYNAMIC_COREUTILS_BIN)/echo" "$$sysroot/echo-cased"; \
	off=$$(grep -abo '/lib/ld-musl-aarch64.so.1' "$$sysroot/echo-cased" | head -1 | cut -d: -f1); \
	[ -n "$$off" ]; \
	printf '/NiX/xd-musl' | dd of="$$sysroot/echo-cased" bs=1 seek="$$off" conv=notrunc 2>/dev/null; \
	out=$$($(ELFUSE_BIN) --sysroot "$$sysroot" "$$sysroot/bin/exec-arg" \
	    /echo-cased echo interp-cased-ok); \
	[ "$$out" = "interp-cased-ok" ]; \
	if [ -e "$$sysroot/NiX" ]; then \
		printf "$(RED)FAIL$(RESET) NiX was stored literally\n"; \
		exit 1; \
	fi

# Exec crosses the escape boundary twice: the path being executed resolves
# like every other guest path, and the identity the kernel reports back
# (/proc/self/exe, /proc/self/fd/N) carries guest bytes. The recipe asserts
# the host-side half: the staged binary sits on disk only under its escape,
# so the passing exec lanes prove the resolution actually crossed it.
## exec paths and the reported exec identity stay in the guest namespace
test-sysroot-exec-names: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-exec-names
	@$(SYSROOT_SCRATCH); \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" \
	    $(BUILD_DIR)/test-sysroot-exec-names; \
	if [ -e "$$tmpdir/Apps" ] && \
	   [ -z "$$(find "$$tmpdir" -maxdepth 1 -name '.ef=*' -print -quit)" ]; then \
		printf "$(RED)FAIL$(RESET) Apps was stored literally\n"; \
		ls -Ab "$$tmpdir"; \
		exit 1; \
	fi

# Watches resolve their path like every other guest path, and event names are
# decoded back to guest bytes. The recipe asserts the host-side half: the
# fixture the guest leaves behind must sit on disk only under its escape, so a
# passing guest lane proves the events were decoded rather than the names
# having been stored literally.
## inotify watches and event names cross the escape boundary intact
test-sysroot-inotify-names: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-inotify-names
	@set -e; \
	tmpdir=$$(mktemp -d); \
	outdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir" "$$outdir"' EXIT; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" \
	    $(BUILD_DIR)/test-sysroot-inotify-names "$$outdir"; \
	if [ -e "$$tmpdir/watch/CaseDir" ] && \
	   [ -z "$$(find "$$tmpdir/watch" -maxdepth 1 -name '.ef=*' -print -quit)" ]; then \
		printf "$(RED)FAIL$(RESET) CaseDir was stored literally\n"; \
		ls -Ab "$$tmpdir/watch"; \
		exit 1; \
	fi

## The degenerate sysroot: a one-character host prefix
test-sysroot-root: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-root
	$(ELFUSE_BIN) --sysroot / $(BUILD_DIR)/test-sysroot-root

## Escape-shaped host names must mean themselves when there is no sysroot
# Same binary as test-sysroot-outside-names: one set of assertions, two
# invocation modes, so the two halves of the scoping contract cannot drift.
test-nosysroot-literal-names: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-outside-names
	@$(SYSROOT_SCRATCH); \
	printf 'literal\n' > "$$tmpdir/.ef=464f4f"; \
	printf 'other\n'   > "$$tmpdir/plain"; \
	$(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-outside-names "$$tmpdir" nosysroot

## Escape-shaped host names must mean themselves outside the sysroot
test-sysroot-outside-names: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-outside-names
	@set -e; \
	srdir=$$(mktemp -d); \
	outdir=$$(mktemp -d); \
	trap 'rm -rf "$$srdir" "$$outdir"' EXIT; \
	printf 'literal\n' > "$$outdir/.ef=464f4f"; \
	$(ELFUSE_BIN) --sysroot "$$srdir" \
	    $(BUILD_DIR)/test-sysroot-outside-names "$$outdir"; \
	if [ -z "$$(find "$$srdir" -maxdepth 1 -name '.ef=*' -print -quit)" ]; then \
		printf "$(RED)FAIL$(RESET) the control name was not escaped, so the volume did not fold\n"; \
		ls -Ab "$$srdir"; \
		exit 1; \
	fi

# A Linux filename is a byte string and a guest may use any of them, but the
# volume underneath decides which two byte strings are the same name, and it
# folds in ways no simple rule predicts. Every pair here is one it considers
# equal and the guest must see as two files.
## Non-ASCII, normalization and case-folding guest filenames
test-sysroot-name-i18n: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-name-i18n
	@$(SYSROOT_SCRATCH); \
	printf 'staged\n' > "$$tmpdir/$$(printf '\346\226\207\346\241\243')-host.txt"; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-sysroot-name-i18n; \
	if [ ! -e "$$tmpdir/$$(printf '\346\226\207\346\241\243')-host.txt" ]; then \
		printf "$(RED)FAIL$(RESET) a host-staged non-ASCII name was disturbed\n"; \
		exit 1; \
	fi

# Linux allows a 255-byte component and a guest is entitled to all of them,
# including for a name stored escaped, which is longer on disk than the name it
# stands for. Nothing below the Linux maximum may be refused.
## Guest filenames at their full length, both stored forms
test-sysroot-name-length: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-name-length
	@$(SYSROOT_SCRATCH); \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-sysroot-name-length

# Component length is a guest budget; whole-path length is a host one, and the
# host's is smaller (macOS PATH_MAX 1024 against Linux's 4096). A guest path
# past the host ceiling reports ENAMETOOLONG and is never truncated; see
# docs/filenames.md, "Whole paths". Not in the qemu matrix: a real Linux
# kernel has no 1024-byte ceiling, so the boundary this pins does not exist
# there.
## Guest paths that cross the host path ceiling report ENAMETOOLONG
test-sysroot-pathmax: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-pathmax
	@$(SYSROOT_SCRATCH); \
	printf 'probe\n' > "$$tmpdir/pathmax-probe"; \
	mode=exact; \
	if [ -e "$$tmpdir/PATHMAX-PROBE" ]; then mode=fold; fi; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" \
	    $(BUILD_DIR)/test-sysroot-pathmax "$$mode"

# Names the guest cannot create for itself, because elfuse would store them
# under a different spelling. A well-formed escape means the name it decodes
# to whoever wrote it; anything that merely resembles one means itself.
#
# No two fixtures here may differ only by case: the staging happens on the host
# with no translation, so a folding volume would merge them and the guest would
# see one file where the recipe meant two. That is why the uppercase-hex case
# uses a payload whose lowercase form is not also staged.
## Host-staged escape-shaped names in a sysroot
test-sysroot-name-staged: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-name-staged
	@$(SYSROOT_SCRATCH); \
	d="$$tmpdir/staged"; \
	mkdir -p "$$d"; \
	printf 'plain\n'          > "$$d/Plain.Host"; \
	printf 'escaped-foo\n'    > "$$d/.ef=464f4f"; \
	printf 'literal-upper\n'  > "$$d/.ef=5A5A"; \
	printf 'literal-odd\n'    > "$$d/.ef=464f4"; \
	printf 'literal-nonhex\n' > "$$d/.ef=zzzz"; \
	printf 'literal-slash\n'  > "$$d/.ef=2f"; \
	printf 'literal-dotdot\n' > "$$d/.ef=2e2e"; \
	printf 'literal-bare\n'   > "$$d/.ef="; \
	printf 'literal-legacy\n' > "$$d/.ef_464f4f"; \
	printf 'literal-bar\n'    > "$$d/Bar"; \
	printf 'shadowed\n'       > "$$d/.ef=426172"; \
	nm="r2probe-$$$$"; \
	Nm="R2Probe-$$$$"; \
	mkdir -p "$$tmpdir/tmp/$$Nm"; \
	mkdir -p "/tmp/$$nm"; \
	printf 'HOST-LEAK\n' > "/tmp/$$nm/planted"; \
	esc="/private/tmp/elfuse-staged-$$$$"; \
	mkdir -p "$$esc/folded" "$$tmpdir$$esc/Folded"; \
	printf 'HOST-LEAK\n' > "$$esc/folded/planted"; \
	trap 'rm -rf "$$tmpdir" "/tmp/'"$$nm"'" "'"$$esc"'"' EXIT; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-sysroot-name-staged \
	    "/tmp/$$nm" "$$esc/folded"; \
	if [ -e "/tmp/$$nm/created" ] || [ -e "$$esc/folded/created" ] || \
	   [ -n "$$(find "$$tmpdir" -name created)" ]; then \
		printf "$(RED)FAIL$(RESET) a create landed under a folded component\n"; \
		exit 1; \
	fi

# A sysroot written by an older elfuse holds the spellings that build froze,
# and the current build must keep reading them. The literals staged here are
# copies of rows in tests/casefold-vectors.h. Keep them in step; the guest
# opens strictly by guest name, so a literal that drifts from the header
# fails at runtime rather than silently testing nothing. Staging happens on
# the host so nothing here derives from the codec under test. Escapes mean
# their guest names only where the escape is active, so a case-sensitive
# scratch volume is a SKIP, not a pass.
## Read a corpus of frozen on-disk spellings staged host-side
test-sysroot-corpus: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-corpus
	@$(SYSROOT_SCRATCH); \
	printf 'p\n' > "$$tmpdir/CaseProbe"; \
	if [ ! -e "$$tmpdir/caseprobe" ]; then \
		printf "$(YELLOW)SKIP$(RESET) test-sysroot-corpus (scratch volume is case-sensitive)\n"; \
		exit 0; \
	fi; \
	rm -f "$$tmpdir/CaseProbe"; \
	c="$$tmpdir/corpus"; \
	mkdir -p "$$c"; \
	printf 'Foo\n' > "$$c/.ef=466f6f"; \
	printf 'README\n' > "$$c/.ef=524541444d45"; \
	printf 'caf\303\251\n' > "$$c/.ef=636166c3a9"; \
	mkdir -p "$$c/.ef=4775657374446972"; \
	printf 'New.File\n' > "$$c/.ef=4775657374446972/.ef=4e65772e46696c65"; \
	long=".ef=$$(printf '\344\271\276')"; \
	i=0; \
	while [ $$i -lt 42 ]; do \
		long="$$long$$(printf '\345\216\205\345\231\230')"; \
		i=$$((i + 1)); \
	done; \
	awk 'BEGIN { for (i = 0; i < 126; i++) printf "X"; printf "\n" }' \
	    > "$$c/$$long"; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-sysroot-corpus

# The volume counterpart of test-sysroot-name-race: minutes of threaded and
# forked churn over one colliding set instead of ten processes aimed at one
# window. Excluded from check for its runtime, so the guest runs with
# --timeout 0; a pass is only the absence of a reproducer today. The header
# of tests/test-sysroot-name-soak.c states the invariants.
## Soak colliding-name churn for SECS seconds (default 120)
test-sysroot-name-soak: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-name-soak
	@$(SYSROOT_SCRATCH); \
	$(ELFUSE_BIN) --timeout 0 --sysroot "$$tmpdir" \
	    $(BUILD_DIR)/test-sysroot-name-soak $(or $(SECS),120)

## Alias for test-sysroot-name-soak
check-soak: test-sysroot-name-soak

# Nothing serializes name creation in a sysroot, because the on-disk spelling of
# a guest name is a function of that name alone. fork(2) under elfuse spawns a
# separate host process, so the children really are separate processes sharing
# one sysroot. Repeated, because a single round can miss a narrow window; a pass
# does not prove there is no race, only a failure proves there is one.
## Concurrent creation of case-colliding names, repeated
test-sysroot-name-race: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-name-race
	@set -e; \
	i=0; \
	tmpdir=""; \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	while [ $$i -lt 10 ]; do \
		tmpdir=$$(mktemp -d); \
		$(ELFUSE_BIN) --sysroot "$$tmpdir" \
		    $(BUILD_DIR)/test-sysroot-name-race > "$$tmpdir/.out" 2>&1 || { \
			cat "$$tmpdir/.out"; rm -rf "$$tmpdir"; exit 1; }; \
		rm -rf "$$tmpdir"; \
		i=$$((i + 1)); \
	done; \
	printf "test-sysroot-name-race: 10 rounds - PASS\n"

# The byte-exact lane is the oracle for the name suite. A case-sensitive
# volume stores every name as itself and matches byte-exactly (the same
# contract the tests assert), so an expectation that fails here disagrees
# with a real Linux filesystem, whatever the folding lane says of it.
# test-sysroot-name-staged stays out: it stages the spellings a folding
# volume forces, and those do not exist here. One image hosts every run,
# with a per-test subdirectory keeping the sysroots apart; the find at the
# end enforces for all tests at once that elfuse stored nothing escaped,
# which is the inversion of the folding lane's stray checks. It prunes the
# path-matrix subtree, because an escape-shaped literal is one of that
# test's name classes: the guest asks for that name and a byte-exact volume
# owes it back unchanged, so an entry there is a guest creation and says
# nothing about what elfuse wrote. A positive check keeps the subtree
# covered instead, since every other lane creates no such name.
# The cross-product matrix asserts mode agreement, an invariant that must
# hold identically whether the volume folds or not; the recipe provisions a
# folding tmpdir, and check-name-caseexact re-runs the same binary on the
# case-sensitive volume.
## Addressing modes agree over operation x shape x name class
test-sysroot-path-matrix: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-path-matrix
	@$(SYSROOT_SCRATCH); \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" \
	    $(BUILD_DIR)/test-sysroot-path-matrix

## Re-run the name suite on a case-sensitive volume as ground truth
check-name-caseexact: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-name-unique \
		$(BUILD_DIR)/test-sysroot-name-relative \
		$(BUILD_DIR)/test-sysroot-name-i18n \
		$(BUILD_DIR)/test-sysroot-name-length \
		$(BUILD_DIR)/test-sysroot-name-race \
		$(BUILD_DIR)/test-sysroot-path-matrix
	@dmg=$$(mktemp -u).dmg; mnt=""; \
	trap '[ -n "$$mnt" ] && hdiutil detach "$$mnt" -force -quiet >/dev/null 2>&1; rm -f "$$dmg"' EXIT; \
	if ! hdiutil create -size 64m -fs "Case-sensitive APFS" \
	        -volname elfusenamecs -quiet "$$dmg" >/dev/null 2>&1; then \
		printf "$(YELLOW)SKIP$(RESET) check-name-caseexact (hdiutil create failed)\n"; \
		exit 0; \
	fi; \
	mnt=$$(hdiutil attach "$$dmg" -nobrowse | awk '/\/Volumes\//{print $$NF}'); \
	if [ -z "$$mnt" ]; then \
		printf "$(YELLOW)SKIP$(RESET) check-name-caseexact (hdiutil attach failed)\n"; \
		exit 0; \
	fi; \
	set -e; \
	for t in name-unique name-i18n name-length; do \
		mkdir -p "$$mnt/$$t"; \
	done; \
	printf 'staged\n' > "$$mnt/name-i18n/$$(printf '\346\226\207\346\241\243')-host.txt"; \
	$(ELFUSE_BIN) --sysroot "$$mnt/name-unique" \
	    $(BUILD_DIR)/test-sysroot-name-unique; \
	mkdir -p "$$mnt/name-relative" "$$mnt/name-relative-outside"; \
	$(ELFUSE_BIN) --sysroot "$$mnt/name-relative" \
	    $(BUILD_DIR)/test-sysroot-name-relative "$$mnt/name-relative-outside"; \
	$(ELFUSE_BIN) --sysroot "$$mnt/name-i18n" \
	    $(BUILD_DIR)/test-sysroot-name-i18n csapfs; \
	mkdir -p "$$mnt/path-matrix"; \
	$(ELFUSE_BIN) --sysroot "$$mnt/path-matrix" \
	    $(BUILD_DIR)/test-sysroot-path-matrix; \
	if [ ! -e "$$mnt/name-i18n/$$(printf '\346\226\207\346\241\243')-host.txt" ]; then \
		printf "$(RED)FAIL$(RESET) a host-staged non-ASCII name was disturbed\n"; \
		exit 1; \
	fi; \
	$(ELFUSE_BIN) --sysroot "$$mnt/name-length" \
	    $(BUILD_DIR)/test-sysroot-name-length; \
	i=0; \
	while [ $$i -lt 3 ]; do \
		mkdir -p "$$mnt/name-race-$$i"; \
		$(ELFUSE_BIN) --sysroot "$$mnt/name-race-$$i" \
		    $(BUILD_DIR)/test-sysroot-name-race > "$$mnt/name-race-$$i/.out" 2>&1 || { \
			cat "$$mnt/name-race-$$i/.out"; exit 1; }; \
		i=$$((i + 1)); \
	done; \
	printf "test-sysroot-name-race: 3 byte-exact rounds - PASS\n"; \
	escaped=$$(find "$$mnt" -path "$$mnt/path-matrix" -prune -o \
	    -name '.ef=*' -print | wc -l | tr -d ' '); \
	if [ "$$escaped" != 0 ]; then \
		printf "$(RED)FAIL$(RESET) %s name(s) escaped on a byte-exact volume\n" "$$escaped"; \
		find "$$mnt" -path "$$mnt/path-matrix" -prune -o -name '.ef=*' -print; \
		exit 1; \
	fi; \
	if [ -z "$$(find "$$mnt/path-matrix" -name 'Mixed.Name' -print -quit)" ]; then \
		printf "$(RED)FAIL$(RESET) path-matrix stored no literal Mixed.Name\n"; \
		find "$$mnt/path-matrix" | head -40; \
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
	@$(SYSROOT_SCRATCH); \
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
	trap 'rm -rf "$$tmpdir"; rm -rf /tmp/elfuse-sysroot-create-paths /tmp/race_dir' EXIT; \
	rm -rf /tmp/elfuse-sysroot-create-paths /tmp/race_dir; \
	mkdir -p "$$host_out_dir"; \
	$(ELFUSE_BIN) --create-sysroot "$$tmpdir/case-sysroot" $(BUILD_DIR)/test-sysroot-create-paths "$$guest_tmp" "$$mounted_tmp" "$$host_out" "$$tmpdir/case-sysroot"; \
	if [ -e "$$guest_tmp" ]; then \
		printf "$(RED)FAIL$(RESET) guest /tmp escaped to host /tmp\n"; \
		exit 1; \
	fi; \
	if [ -e /tmp/race_dir ]; then \
		printf "$(RED)FAIL$(RESET) TOCTOU race created a directory outside the sysroot\n"; \
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

## Magic link (/proc/self/fd/<n>, /dev/fd/<n>) resolution. Runs in a throwaway
## sysroot so the fixtures it creates at the guest root land in the tmpdir.
test-sysroot-fd-magiclink: $(ELFUSE_BIN) $(BUILD_DIR)/test-fd-magiclink
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	mkdir -p "$$tmpdir/bin"; \
	cp $(BUILD_DIR)/test-fd-magiclink "$$tmpdir/bin/test-fd-magiclink"; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" "$$tmpdir/bin/test-fd-magiclink"

test-timeout-disable: $(ELFUSE_BIN) $(TEST_HELLO_DEP)
	@$(ELFUSE_BIN) --timeout 0 $(TEST_DIR)/test-hello > /dev/null

## Verify --user / --workdir / --fakeroot reject contradictory requests before
## guest bring-up, and that --env / --clear-env reach the guest's environ.
test-launch-flags: $(ELFUSE_BIN) $(TEST_HELLO_DEP) $(TEST_ENV_DEPS)
	@bash tests/test-launch-flags.sh $(ELFUSE_BIN) $(TEST_DIR)/test-hello \
	    $(TEST_DIR)/test-env-dump $(TEST_DIR)/test-cat

## Check the --help and argument-error usage synopses against each other
test-usage-synopsis: $(ELFUSE_BIN)
	@bash tests/test-usage-synopsis.sh $(ELFUSE_BIN)

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

# The probe is built only when the cross-glibc sysroot exists; without it the
# lane still covers the launcher and reports the probe arm as skipped.
# The launcher binaries are fetched by tests/fetch-sharun-bin.sh, not listed
# here: a make prerequisite that cannot be downloaded is fatal, and this lane
# runs inside "make check". Fetching from the script lets an unreachable
# network degrade to a skip, the same way the glibc package already does.
TEST_SHARUN_PROBE_DIR :=
ifneq ($(CROSS_GLIBC_SYSROOT_PRESENT),)
  TEST_SHARUN_PROBE_DIR := $(BUILD_DIR)
endif

## Run sharun and its probe under elfuse: the prebuilt launcher and the
## cross-built probe always, plus a bundle assembled from those two.
test-sharun: $(ELFUSE_BIN) $(TEST_SHARUN_PROBE_DIR:%=%/probe)
	$(call RUN_OPTIONAL_SKIP77,FIXTURES_DIR="$(FIXTURES_DIR)" CROSS_COMPILE="$(CROSS_COMPILE)" SHARUN_FIXTURE_DIR="$(SHARUN_FIXTURE_DIR)" MATRIX_ROSETTA_TRANSLATOR="$(MATRIX_ROSETTA_TRANSLATOR)" ELFUSE_NO_ROSETTA="$(ELFUSE_NO_ROSETTA)" TEST_TIMEOUT="$(TEST_TIMEOUT)" bash tests/test-sharun.sh $(ELFUSE_BIN) $(TEST_SHARUN_PROBE_DIR),test-sharun)

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

# String builder unit test
## Run the growable string builder host unit test
test-string-builder-host: $(BUILD_DIR)/test-string-builder-host
	$(BUILD_DIR)/test-string-builder-host

# Generic dynamic array unit test
## Run the raw/typed dynamic array host unit test
test-dynamic-array-host: $(BUILD_DIR)/test-dynamic-array-host
	$(BUILD_DIR)/test-dynamic-array-host

# vCPU run-loop hook API regression
## Run the vCPU run-loop hook API unit test
test-vcpu-run-hooks-host: $(BUILD_DIR)/test-vcpu-run-hooks-host
	$(BUILD_DIR)/test-vcpu-run-hooks-host

# Proctitle argv-tail regression
## Run the deterministic argv-tail overshoot guard test
test-proctitle-host: $(BUILD_DIR)/test-proctitle-host
	$(BUILD_DIR)/test-proctitle-host

# Filename codec unit test. The binary takes a directory, so the same test can
# be pointed at another volume:
#   build/test-casefold-host /Volumes/case-sensitive-image
## Run the filename codec unit tests against a scratch directory
test-casefold-host: $(BUILD_DIR)/test-casefold-host
	$(BUILD_DIR)/test-casefold-host

# Case-exact path resolution unit test. Also takes a directory.
## Run the case-exact path resolution unit tests
test-casefold-walk-host: $(BUILD_DIR)/test-casefold-walk-host
	$(BUILD_DIR)/test-casefold-walk-host

## Run the absock derived-name unit test natively on the host
test-absock-names-host: $(BUILD_DIR)/test-absock-names-host
	$(BUILD_DIR)/test-absock-names-host

# Wakeup pipe concurrency unit test. Only a -fsanitize=thread build carries a
# race detector, so check-sanitizer is where this lane has its full weight.
## Run the wakeup pipe concurrency unit test natively on the host
test-wakeup-pipe-host: $(BUILD_DIR)/test-wakeup-pipe-host
	$(BUILD_DIR)/test-wakeup-pipe-host

## Run the guest environment merge cross product
test-guest-env-host: $(BUILD_DIR)/test-guest-env-host
	$(BUILD_DIR)/test-guest-env-host

# Volume naming probe
## Report how the filesystem treats filenames (regenerates docs/filenames.md tables)
probe-volume-naming: $(BUILD_DIR)/probe-volume-naming
	$(BUILD_DIR)/probe-volume-naming

# Shebang parser unit test
## Run shebang parsing unit tests
test-shebang-host: $(BUILD_DIR)/test-shebang-host
	$(BUILD_DIR)/test-shebang-host

## Run the proved/gva.h call-site precondition checks (skips without the flag)
test-gva-contracts: $(BUILD_DIR)/test-gva-contracts
	$(BUILD_DIR)/test-gva-contracts
