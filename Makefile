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
    core/guest-env.c \
    core/launch.c \
    core/rosetta.c \
    core/sysroot.c \
    runtime/thread.c \
    runtime/futex.c \
    runtime/forkipc.c \
    runtime/fork-state.c \
    runtime/procemu.c \
    runtime/procemu-pty.c \
    runtime/usb-sysfs.c \
    runtime/usb-desc.c \
    runtime/proctitle.c \
    syscall/syscall.c \
    syscall/fdtable.c \
    syscall/translate.c \
    syscall/mem.c \
    syscall/path.c \
    syscall/fuse.c \
    syscall/casefold.c \
    syscall/casefold-walk.c \
    syscall/chown-overlay.c \
    syscall/fs.c \
    syscall/fs-stat.c \
    syscall/fs-xattr.c \
    syscall/io.c \
    syscall/poll.c \
    syscall/wakeup-pipe.c \
    syscall/fd.c \
    syscall/asyncio.c \
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
    syscall/net-identity.c \
    syscall/net-absock.c \
    syscall/net-sockopt.c \
    syscall/netlink.c \
    syscall/sysvipc.c \
    debug/crashreport.c \
    debug/gdbstub.c \
    debug/gdbstub-reg.c \
    debug/gdbstub-rsp.c \
    debug/log.c \
    debug/syscall-hist.c

SRCS := $(addprefix src/,$(SRCS))
OBJS := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(SRCS))

DISPATCH_MANIFEST := src/syscall/dispatch.tbl
DISPATCH_GENERATOR := scripts/gen-syscall-dispatch.py
DISPATCH_HEADER := $(BUILD_DIR)/dispatch.h
HVF_LDFLAGS := -framework Hypervisor -framework IOKit -framework CoreFoundation -arch arm64

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
.PHONY: all elfuse install-hooks uninstall-hooks
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

## Install the repository's Git hooks without replacing local hooks
install-hooks:
	@$(HOOK_INSTALLER)

## Remove hooks that install-hooks created, leaving any local hook alone
uninstall-hooks:
	@$(HOOK_INSTALLER) --uninstall

$(ELFUSE_BIN): $(OBJS) | $(BUILD_DIR)
	$(call link-and-sign,$@,$(OBJS))

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

## Build the vCPU run-loop hook API compile test (native macOS binary).
$(BUILD_DIR)/test-vcpu-run-hooks-host: \
		$(BUILD_DIR)/test-vcpu-run-hooks-host.o | $(BUILD_DIR)
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

## Build the ELF header validation host test (native macOS binary)
$(BUILD_DIR)/test-elf-headers-host: $(BUILD_DIR)/test-elf-headers-host.o \
		$(BUILD_DIR)/core/elf.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the teardown live-worker accounting host unit test (native macOS binary)
# Links the in-tree thread.o so the real thread_destroy_all_vcpus logic runs.
# It drives only the worker branches (main vCPU passed as not-valid), so no
# hv_vcpu_destroy is ever called and no HVF entitlement is needed; the framework
# is linked only to resolve thread.o's hv_* references.
$(BUILD_DIR)/test-teardown-live-vcpu-host: \
		$(BUILD_DIR)/test-teardown-live-vcpu-host.o \
		$(BUILD_DIR)/runtime/thread.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(HVF_LDFLAGS)

## Build the buffered GDB session host regression
$(BUILD_DIR)/test-gdbstub-host: $(BUILD_DIR)/test-gdbstub-host.o \
		$(BUILD_DIR)/debug/gdbstub-reg.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(HVF_LDFLAGS)

## Build the proved/gva.h contract-check host test (native macOS binary)
# Header-only: proved/gva.h is static inline, so the test links nothing
# from the project. It skips unless the build defines ELFUSE_CONTRACT_ASSERT,
# which is what "make check-contracts" does.
$(BUILD_DIR)/test-gva-contracts: $(BUILD_DIR)/test-gva-contracts.o \
		| $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the volume naming probe (native macOS binary)
# Standalone: it measures the filesystem, so it links nothing from the project.
$(BUILD_DIR)/probe-volume-naming: $(BUILD_DIR)/probe-volume-naming.o \
		| $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the filename codec host test (native macOS binary)
# casefold.o is a leaf translation unit with no syscall-layer dependencies, so
# the test links exactly the code under test and nothing else.
$(BUILD_DIR)/test-casefold-host: $(BUILD_DIR)/test-casefold-host.o \
		$(BUILD_DIR)/syscall/casefold.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the wakeup pipe concurrency host test (native macOS binary)
# wakeup-pipe.o is a leaf translation unit, so the test links the code under
# test and nothing else.
$(BUILD_DIR)/test-wakeup-pipe-host: $(BUILD_DIR)/test-wakeup-pipe-host.o \
		$(BUILD_DIR)/syscall/wakeup-pipe.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the case-exact path resolution host test (native macOS binary)
# Links the resolver and the codec; the two process-state symbols the resolver
# reads are stubbed in the test.
$(BUILD_DIR)/test-casefold-walk-host: $(BUILD_DIR)/test-casefold-walk-host.o \
		$(BUILD_DIR)/syscall/casefold-walk.o \
		$(BUILD_DIR)/syscall/casefold.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/test-absock-names-host: $(BUILD_DIR)/test-absock-names-host.o \
		$(BUILD_DIR)/syscall/net-absock.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the string builder host unit test (native macOS binary)
# Header-only now, so the test needs no object but its own; skip the
# Hypervisor framework and codesign.
$(BUILD_DIR)/test-string-builder-host: \
		$(BUILD_DIR)/test-string-builder-host.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the generic dynamic-array host unit test (native macOS binary)
# Header-only container; the test compiles it in through utils.h.
$(BUILD_DIR)/test-dynamic-array-host: \
		$(BUILD_DIR)/test-dynamic-array-host.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the USB descriptor walk host unit test (native macOS binary)
# usb-desc.o is a pure leaf translation unit (byte bookkeeping, no IOKit and no
# I/O), so the test links the code under test and nothing else.
$(BUILD_DIR)/test-usb-desc-host: $(BUILD_DIR)/test-usb-desc-host.o \
		$(BUILD_DIR)/runtime/usb-desc.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the guest environment merge host test (native macOS binary)
# guest-env.o's only dependency is the log macro, which the test stubs.
$(BUILD_DIR)/test-guest-env-host: $(BUILD_DIR)/test-guest-env-host.o \
		$(BUILD_DIR)/core/guest-env.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

# test-stdio-nonblock-host launches elfuse with a pipe as stdin and checks the
# flags on its own end of that pipe afterwards, so it is a host binary. It sits
# outside the guest-binary guard below because check requires it through
# CHECK_HOST_UNIT_BINS whether or not the guest binaries are pre-built.
$(BUILD_DIR)/test-stdio-nonblock-host: tests/test-stdio-nonblock-host.c | $(BUILD_DIR)
	@echo "  CC      $<"
	$(Q)$(CC) $(CFLAGS) -Itests -o $@ $<

# Guest test binaries (cross-compiled, aarch64-linux)
# Only used when GUEST_TEST_BINARIES is not set.

# Before the "ifndef GUEST_TEST_BINARIES" block below, and outside it. Two
# rules name this stamp: the glibc benchmark inside that block and the sharun
# fixtures outside it. Defined inside, a prebuilt-guest-binaries build left it
# empty and the fixtures took a blank prerequisite; defined after the block, the
# benchmark took one. Ahead of both is the only spot that serves both.
#
# The identity is in the stamp's name, not its contents, so a switched toolchain
# names a file that does not exist and the fixtures rebuild on the ordinary
# missing-prerequisite rule. Writing the identity into a fixed name instead
# needs a phony prerequisite to re-run a comparison on every build, and that
# also makes "make -n" report a rebuild a real build does not do, because a dry
# run assumes the recipe wrote the file.
#
# A real target, not a write while the makefile is read: the FLAVOR stamp in
# mk/common.mk is written at parse time, which it can be because nothing names
# it as a prerequisite, whereas a parse-time write here would happen before
# "make clean test-sharun" runs clean and leave the fixtures naming a
# prerequisite that no longer exists and has no rule to recreate it.
CROSS_GLIBC_STAMP := $(BUILD_DIR)/.sharun-toolchain-$(CROSS_GLIBC_ID_HASH)
$(CROSS_GLIBC_STAMP): | $(BUILD_DIR)

	# Exactly one stamp exists at a time. Leaving the old ones behind means
	# switching back to a toolchain used earlier finds its stamp still there and
	# older than the fixtures the other toolchain built, so make calls them up to
	# date and the lane runs binaries linked against the wrong runtime.
	$(Q)rm -f $(BUILD_DIR)/.sharun-toolchain-*
	$(Q)touch $@

ifndef GUEST_TEST_BINARIES
$(BUILD_DIR)/test-hello: tests/hello.S tests/simple.ld | $(BUILD_DIR)
	@echo "  AS      tests/hello.S"
	$(Q)$(BAREMETAL_CROSS)as -o $(BUILD_DIR)/test-hello.o tests/hello.S
	@echo "  LD      $@"
	$(Q)$(BAREMETAL_CROSS)ld -T tests/simple.ld -o $@ $(BUILD_DIR)/test-hello.o

# Pattern rule: cross-compile tests/*.c to static aarch64-linux binaries
# -D_GNU_SOURCE exposes pipe2/dup3/O_DIRECT/etc. on glibc (musl exposes them by default)
# -MMD tracks the shared test headers, so editing one rebuilds every guest
# binary that includes it. Compiling and linking in one step, the driver
# injects -MQ with the -o argument unless -MT or -MQ is given, so the rule
# target is the binary and the .d lands where mk/common.mk -includes it.
CROSS_TEST_CFLAGS = -D_GNU_SOURCE -static -O2 -MMD -MP
$(BUILD_DIR)/%: tests/%.c | $(BUILD_DIR)
	@echo "  CROSS   $<"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $<

# test-eventfd-semaphore-contended races two blocking readers on one eventfd.
$(BUILD_DIR)/test-eventfd-semaphore-contended: \
		tests/test-eventfd-semaphore-contended.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-signal-in-shim aims a stream of signals at threads contending for one
# mutex, so the kick lands while a vCPU is inside the EL1 shim.
$(BUILD_DIR)/test-signal-in-shim: tests/test-signal-in-shim.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-dir-union-fd-reuse closes the walked directory fd from a second thread
# while the first is inside the widened union backing-lookup window.
$(BUILD_DIR)/test-dir-union-fd-reuse: \
		tests/test-dir-union-fd-reuse.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-fstatfs-fd-identity replaces the slot from a second thread while the
# first is inside the widened fd-identity window.
$(BUILD_DIR)/test-fstatfs-fd-identity: \
		tests/test-fstatfs-fd-identity.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-fd-pin-lock keeps a sibling thread live so the fd syscalls under test
# take the multi-threaded pin path rather than the single-active fast path.
$(BUILD_DIR)/test-fd-pin-lock: \
		tests/test-fd-pin-lock.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-socket-accept-contended parks two threads on one listener.
$(BUILD_DIR)/test-socket-accept-contended: \
		tests/test-socket-accept-contended.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-socket-waitall drips the tail of a MSG_WAITALL request from a second
# thread.
$(BUILD_DIR)/test-socket-waitall: tests/test-socket-waitall.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-dup-setfl-race races a dup against an F_SETFL sweep from a second thread.
$(BUILD_DIR)/test-dup-setfl-race: tests/test-dup-setfl-race.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-uevent-socket races two threads through socket(AF_NETLINK) and parks a
# blocking receive until a second thread pokes the rtnetlink fd.
$(BUILD_DIR)/test-uevent-socket: tests/test-uevent-socket.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-pthread needs -lpthread
$(BUILD_DIR)/test-pthread: tests/test-pthread.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-sysroot-name-soak churns from worker threads plus forked children
$(BUILD_DIR)/test-sysroot-name-soak: tests/test-sysroot-name-soak.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-process-lifecycle creates a worker to verify that process PIDs and
# thread TIDs share one namespace-wide allocator across fork children.
$(BUILD_DIR)/test-process-lifecycle: tests/test-process-lifecycle.c src/utils.h | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -Isrc -o $@ $< -lpthread

# test-sigsuspend parks two threads on one process-directed signal.
$(BUILD_DIR)/test-sigsuspend: tests/test-sigsuspend.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -Itests -o $@ $< -lpthread

# bench-mmap has a multi-threaded mmap_lock-contention section; needs -lpthread.
$(BUILD_DIR)/bench-mmap: tests/bench-mmap.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-mmap-lazy races concurrent first touch from several threads.
$(BUILD_DIR)/test-mmap-lazy: tests/test-mmap-lazy.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

.PHONY: test-mmap-lazy
test-mmap-lazy: $(ELFUSE_BIN) $(BUILD_DIR)/test-mmap-lazy
	@$(ELFUSE_BIN) $(BUILD_DIR)/test-mmap-lazy
	@sh tests/test-mmap-dirty-stats.sh $(ELFUSE_BIN) \
		$(BUILD_DIR)/test-mmap-lazy

# EL1 consumer-mmap integration/stress test.
$(BUILD_DIR)/test-mmap-fastpath: tests/test-mmap-fastpath.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

.PHONY: test-mmap-fastpath
test-mmap-fastpath: $(ELFUSE_BIN) $(BUILD_DIR)/test-mmap-fastpath
	@$(ELFUSE_BIN) $(BUILD_DIR)/test-mmap-fastpath
	@sh tests/test-mmap-fastpath-stats.sh $(ELFUSE_BIN) \
		$(BUILD_DIR)/test-mmap-fastpath

# test-thread-churn creates >64 threads to force thread-table slot reuse.
$(BUILD_DIR)/test-thread-churn: tests/test-thread-churn.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-threaded-exec execs itself repeatedly with live sibling threads.
$(BUILD_DIR)/test-threaded-exec: tests/test-threaded-exec.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-sigpipe needs a thread to close the reader mid-write.
$(BUILD_DIR)/test-sigpipe: tests/test-sigpipe.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -Itests -o $@ $< -lpthread

# test-pipe-steal contends several readers for one byte, then execs on top.
$(BUILD_DIR)/test-pipe-steal: tests/test-pipe-steal.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -Itests -o $@ $< -lpthread

# test-exec-handoff parks the leader while a worker hands it a failing execve.
$(BUILD_DIR)/test-exec-handoff: tests/test-exec-handoff.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-cntvct-thread verifies cloned vCPUs inherit EL0 timer access.
$(BUILD_DIR)/test-cntvct-thread: tests/test-cntvct-thread.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-poll uses pthread_kill to verify blocked read signal delivery.
$(BUILD_DIR)/test-poll: tests/test-poll.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-tgkill-directed verifies thread-directed (pthread_kill/tgkill) routing.
$(BUILD_DIR)/test-tgkill-directed: tests/test-tgkill-directed.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-sigtimedwait uses a sender pthread to verify thread-directed waits.
$(BUILD_DIR)/test-sigtimedwait: tests/test-sigtimedwait.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-osync-requeue drives a raw FUTEX_REQUEUE against a plain-FUTEX_WAIT
# waiter (musl unlock_requeue pattern) to guard the os_sync wake-at-source
# degradation; needs -lpthread.
$(BUILD_DIR)/test-osync-requeue: tests/test-osync-requeue.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-scm-creds blocks accept in a pthread while the listener option changes.
$(BUILD_DIR)/test-scm-creds: tests/test-scm-creds.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-fault-signal-mt spawns pthreads that each take recoverable SIGSEGVs to
# stress synchronous-fault delivery routing in a multi-threaded guest.
$(BUILD_DIR)/test-fault-signal-mt: tests/test-fault-signal-mt.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-exit-group-worker has a non-main pthread issue exit_group while
# spinner threads hammer memory, guarding the join-before-teardown order.
$(BUILD_DIR)/test-exit-group-worker: tests/test-exit-group-worker.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-shim-cred-race spawns a pthread reader while the main thread
# toggles setresuid; the reader spins on the identity fast path.
$(BUILD_DIR)/test-shim-cred-race: tests/test-shim-cred-race.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-mprotect-mt stresses multi-vCPU mprotect under concurrent reader
# threads to surface stale-TLB regressions.
$(BUILD_DIR)/test-mprotect-mt: tests/test-mprotect-mt.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-shim-urandom-smp spawns N pthreads racing on a shared FD_URANDOM
# slot to exercise the shim's LDXR/STXR head-advance under contention.
$(BUILD_DIR)/test-shim-urandom-smp: tests/test-shim-urandom-smp.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-shim-urandom-toctou races mprotect(PROT_NONE) against urandom
# reads to exercise the EL1 data abort recovery path. Needs pthreads.
$(BUILD_DIR)/test-shim-urandom-toctou: tests/test-shim-urandom-toctou.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-futex-requeue-account parks a waiter, requeues it, and parks another, so
# it needs threads.
$(BUILD_DIR)/test-futex-requeue-account: tests/test-futex-requeue-account.c \
    | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-futex-wake-nowaiter races a waker against a waiter to prove the EL1 wake
# path never answers 0 for an address that still has one, so it needs a thread.
$(BUILD_DIR)/test-futex-wake-nowaiter: tests/test-futex-wake-nowaiter.c \
    | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-shim-futex-fast spawns a waker thread for the matching-word case, which
# is the one branch of the futex fast path that must decline and block.
$(BUILD_DIR)/test-shim-futex-fast: tests/test-shim-futex-fast.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-shim-futex-toctou races mprotect(PROT_NONE) against the futex EL1 ldtr
# to exercise its data abort recovery slot. Needs pthreads.
$(BUILD_DIR)/test-shim-futex-toctou: tests/test-shim-futex-toctou.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-fuse-basic runs a guest daemon thread and consumer in one process
$(BUILD_DIR)/test-fuse-basic: tests/test-fuse-basic.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-sched-policy spawns a pthread to verify per-thread TID lookup
$(BUILD_DIR)/test-sched-policy: tests/test-sched-policy.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-signalfd-hardening needs -lpthread for the worker-thread tid
# regression case in test_rt_sigqueueinfo_rejects_thread_tid.
$(BUILD_DIR)/test-signalfd-hardening: tests/test-signalfd-hardening.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-futex-waitv needs -lpthread for the host wake-thread used to unblock
# the main thread's futex_waitv.
$(BUILD_DIR)/test-futex-waitv: tests/test-futex-waitv.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# test-fork-lowbase must be a non-PIE ET_EXEC linked below ELF_DEFAULT_BASE so
# nested forks exercise elf_load_min preservation across fork IPC.
$(BUILD_DIR)/test-fork-lowbase: tests/test-fork-lowbase.c | $(BUILD_DIR)
	@echo "  CROSS   $< (low-base ET_EXEC)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -no-pie \
		-Wl,-Ttext-segment=0x200000 -o $@ $<

# test-lowbase-mem variants must be non-PIE ET_EXEC binaries linked below
# ELF_DEFAULT_BASE so mprotect/munmap exercise the old low-address reject
# window at two offsets.
$(BUILD_DIR)/test-lowbase-mem-200000: tests/test-lowbase-mem.c | $(BUILD_DIR)
	@echo "  CROSS   $< (low-base ET_EXEC @0x200000)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -no-pie \
		-Wl,-Ttext-segment=0x200000 -o $@ $<

$(BUILD_DIR)/test-lowbase-mem-300000: tests/test-lowbase-mem.c | $(BUILD_DIR)
	@echo "  CROSS   $< (low-base ET_EXEC @0x300000)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -no-pie \
		-Wl,-Ttext-segment=0x300000 -o $@ $<

# bench-hot-guard grew a bulk lane with a draining thread and a lane that runs
# with a sibling alive, so it needs -lpthread; the pattern rule does not link it.
$(BUILD_DIR)/bench-hot-guard: tests/bench-hot-guard.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

# bench-futex-contend is the workload that decides what the futex fast paths are
# worth: contended mutexes plus a condvar handoff, which is what glibc and musl
# locking actually issue. It is what showed that a wake with no waiter is 59.8
# percent of futex calls there while the wait fast path fires not once, the
# reverse of what a two-thread ping-pong suggests. Run by hand, not a gate.
$(BUILD_DIR)/bench-futex-contend: tests/bench-futex-contend.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

.PHONY: bench-futex-contend
bench-futex-contend: $(ELFUSE_BIN) $(BUILD_DIR)/bench-futex-contend
	$(Q)ELFUSE_SHIM_STATS=1 $(ELFUSE_BIN) $(BUILD_DIR)/bench-futex-contend

# bench-futex is the comprehensive futex bench: uncontended fast-path rows plus
# threaded wake/wait handoff, so it links -lpthread like bench-hot-guard above.
# Run by hand (make bench-futex); it is not a gate, because handoff latency is a
# host-scheduler measurement and would flake as one. The rows that can be gated
# live in bench-hot-guard instead.
$(BUILD_DIR)/bench-futex: tests/bench-futex.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc $(CROSS_TEST_CFLAGS) -o $@ $< -lpthread

.PHONY: bench-futex
bench-futex: $(ELFUSE_BIN) $(BUILD_DIR)/bench-futex
	$(Q)$(ELFUSE_BIN) $(BUILD_DIR)/bench-futex

# bench-hot-guard-glibc is the dynamic-glibc twin of bench-hot-guard.
# Built only when the cross-glibc toolchain ships its own sysroot
# (so a host without that toolchain can still run the rest of the
# suite). Linked without -static so glibc resolves time / urandom
# syscalls through the vDSO trampoline -- which is exactly what the
# guardrail script verifies against the 50 ns / 200 ns ceilings.
ifneq ($(CROSS_GLIBC_SYSROOT_PRESENT),)
# -DGUARD_USE_LIBC_CG switches the bench's clock_gettime case from a
# direct vDSO trampoline call to the libc wrapper, so the dynamic-glibc
# build measures glibc's actual routing decision. A regression in the
# NT_GNU_ABI_TAG note or LINUX_2.6.39 versioning would push this
# measurement from ~7 ns up to SVC time (~2000 ns) and fail the
# guardrail.
$(BUILD_DIR)/bench-hot-guard-glibc: tests/bench-hot-guard.c \
		$(CROSS_GLIBC_STAMP) | $(BUILD_DIR)
	@echo "  CROSS   $< (dynamic glibc)"
	$(Q)$(CROSS_COMPILE)gcc --sysroot=$(CROSS_GLIBC_SYSROOT) \
		-D_GNU_SOURCE -DGUARD_USE_LIBC_CG=1 -O2 -o $@ $< -lpthread
endif

endif

## Build the libc-based file-backed mremap EMFILE regression probe
$(BUILD_DIR)/test-mremap-tail-emfile: tests/test-mremap-tail-emfile.c | $(BUILD_DIR)
	@echo "  CROSS   $<"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $<

# Deliberately outside the "ifndef GUEST_TEST_BINARIES" block that ends above:
# mk/tests.mk makes build/probe a prerequisite of test-sharun whenever a cross
# glibc is present, regardless of GUEST_TEST_BINARIES, so a rule hidden by that
# guard would leave the lane with no way to build what it requires.
#
# The sharun probe and its two DSOs, for test-sharun. Dynamic on purpose:
# the point is the loader path (DT_NEEDED, dlopen, $$ORIGIN rpath), so a static
# link would test nothing. Built only when the cross-glibc toolchain ships its
# own sysroot, same guard as bench-hot-guard-glibc above.
#
# All three land in $(BUILD_DIR) together so the probe's $$ORIGIN rpath finds
# libprobe.so at load time and libprobe-dlopen.so at dlopen time, with no
# LD_LIBRARY_PATH. libprobe-dlopen.so is deliberately not linked into the probe,
# so it can only arrive through dlopen.
ifneq ($(CROSS_GLIBC_SYSROOT_PRESENT),)
# Which toolchain and sysroot the fixtures below were built against. Make
# compares timestamps, and neither of those is a file, so a probe built against
# one glibc looks up to date after a switch to another and the lane then runs it
# against a sysroot it was never linked for.
#
$(BUILD_DIR)/libprobe.so $(BUILD_DIR)/libprobe-dlopen.so: \
		$(BUILD_DIR)/lib%.so: tests/fixtures/sharun/%-lib.c \
		$(CROSS_GLIBC_STAMP) | $(BUILD_DIR)
	@echo "  CROSS   $< (shared)"
	$(Q)$(CROSS_COMPILE)gcc --sysroot=$(CROSS_GLIBC_SYSROOT) -fPIC -shared -o $@ $<

$(BUILD_DIR)/probe: tests/fixtures/sharun/probe.c \
		$(BUILD_DIR)/libprobe.so $(BUILD_DIR)/libprobe-dlopen.so \
		$(CROSS_GLIBC_STAMP) | $(BUILD_DIR)
	@echo "  CROSS   $< (dynamic glibc)"
	$(Q)$(CROSS_COMPILE)gcc --sysroot=$(CROSS_GLIBC_SYSROOT) -o $@ $< \
		-L$(BUILD_DIR) -lprobe -ldl -lm -pthread -Wl,-rpath,'$$ORIGIN'
endif

include mk/tests.mk
include mk/lint.mk
include mk/verify.mk
include mk/format.mk
include mk/help.mk
include mk/oci.mk
