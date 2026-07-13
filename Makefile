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
HVF_LDFLAGS := -framework Hypervisor -arch arm64

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
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-poll uses pthread_kill to verify blocked read signal delivery.
$(BUILD_DIR)/test-poll: tests/test-poll.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-tgkill-directed verifies thread-directed (pthread_kill/tgkill) routing.
$(BUILD_DIR)/test-tgkill-directed: tests/test-tgkill-directed.c | $(BUILD_DIR)
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

# test-exit-group-worker has a non-main pthread issue exit_group while
# spinner threads hammer memory, guarding the join-before-teardown order.
$(BUILD_DIR)/test-exit-group-worker: tests/test-exit-group-worker.c | $(BUILD_DIR)
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
