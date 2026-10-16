# Project configuration

ENTITLEMENTS := entitlements.plist
SIGN_IDENTITY ?= -
BUILD_DIR := build

# The USB loopback fixture, off by default.
#
# src/syscall/usbdev-fixture.c models one IOKit device that echoes back what
# was written to it, so the async URB engine can be driven with no board
# attached. The synthetic USB tree in runtime/usb-sysfs.c earns its place in the
# product because it lets lsusb work on a machine with no devices; a device that
# echoes back what was written to it earns nothing outside a test, so it is not
# in the shipped binary. The default build links
# src/syscall/usbdev-fixture-stub.c instead, which answers the same seam and
# models nothing. USB_LOOPBACK_FIXTURE=1 swaps the two (see the SRCS block in
# the top-level Makefile).
#
# The loopback lanes of make check need a binary that has it, and get one under
# a name of its own so a plain make still leaves build/elfuse free of it.
#
# The name is where the two flavors are kept apart, because nothing else keeps
# them apart. The switch changes SRCS and not CFLAGS, and the flavor stamp in
# mk/common.mk is $(strip $(CFLAGS)), so it never trips on this: with both
# flavors linking to build/elfuse, "make USB_LOOPBACK_FIXTURE=1 elfuse" followed
# by "make elfuse" printed "Nothing to be done" and left the fixture in the
# binary a plain make had just been asked for -- measured before this split, nm
# still finding _usbdev_fixture_lock in build/elfuse until a make clean. The
# byte counts for that build are dated in docs/internals.md and not repeated
# here, because the sequence cannot be run again to re-measure them. What is
# guaranteed now is that the fixture build and the shipped build never write
# the same path, so the shipped one cannot be a stale copy of the other; the
# objects are still shared, which is correct, because the only translation
# unit the switch changes is the fixture seam's own and every other object
# is compiled with identical flags. .ci/check-usb-fixture-bin.sh holds the
# two paths apart.
USB_LOOPBACK_FIXTURE ?= 0
ELFUSE_LOOPBACK_BIN := $(BUILD_DIR)/elfuse-loopback
ifeq ($(USB_LOOPBACK_FIXTURE),1)
ELFUSE_BIN := $(ELFUSE_LOOPBACK_BIN)
else
ELFUSE_BIN := $(BUILD_DIR)/elfuse
endif
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "unknown")

# Private pseudo-syscall number used by translated guests to invoke the
# embedder HVC 6 hook. This is not a Linux syscall number.
ELFUSE_NR_EMBEDDER_HVC6 ?= 999

# Test binary directory: either pre-built via GUEST_TEST_BINARIES,
# auto-detected from build/bin, or locally cross-compiled via $(CROSS_COMPILE)gcc.
ifeq ($(origin GUEST_TEST_BINARIES), undefined)
  ifneq ($(wildcard $(BUILD_DIR)/bin/test-hello),)
    GUEST_TEST_BINARIES := $(BUILD_DIR)
  endif
endif

# Exclude native macOS test files from cross-compilation
NATIVE_TESTS := tests/test-multi-vcpu.c tests/test-rwx.c \
                tests/test-tlbi-encoder-host.c \
                tests/test-fork-ipc-protocol-host.c \
                tests/test-casefold-host.c \
                tests/test-casefold-walk-host.c \
                tests/test-absock-names-host.c \
                tests/probe-volume-naming.c \
                tests/probe-disk-writes.c \
                tests/test-dynamic-array-host.c \
                tests/test-string-builder-host.c \
                tests/test-wakeup-pipe-host.c \
                tests/test-stdio-nonblock-host.c \
                tests/test-guest-env-host.c \
                tests/test-usb-desc-host.c \
                tests/test-usbdev-urb-host.c \
                tests/test-elf-headers-host.c \
                tests/test-gdbstub-host.c
SPECIAL_TEST_SRCS := tests/test-lowbase-mem.c
SPECIAL_TEST_BINS := $(BUILD_DIR)/test-lowbase-mem-200000 $(BUILD_DIR)/test-lowbase-mem-300000

# x86_64-only sources that back the vendored Rosetta fixtures in
# tests/fixtures/rosetta/. They are not buildable with the aarch64
# cross-toolchain and would fail link with undefined dlopen/pthread
# symbols even if compiled, so exclude them from the aarch64 glob.
ROSETTA_X86_64_SRCS := $(wildcard tests/x86_64-glibc-*.c tests/x86_64-rosetta-*.c)

ifdef GUEST_TEST_BINARIES
  TEST_DIR  := $(GUEST_TEST_BINARIES)/bin
  TEST_DEPS :=
  TEST_HELLO_DEP :=
  # A prebuilt tree predates test-env-dump, so the environment lanes of
  # test-launch-flags.sh skip themselves rather than fail there.
  TEST_ENV_DEPS :=
else
  TEST_DIR  := $(BUILD_DIR)
  TEST_C_SRCS := $(filter-out $(NATIVE_TESTS) $(SPECIAL_TEST_SRCS) $(ROSETTA_X86_64_SRCS),$(wildcard tests/*.c))
  TEST_C_BINS := $(patsubst tests/%.c,$(BUILD_DIR)/%,$(TEST_C_SRCS))
  TEST_DEPS := $(BUILD_DIR)/test-hello $(TEST_C_BINS) $(SPECIAL_TEST_BINS)
  TEST_HELLO_DEP := $(BUILD_DIR)/test-hello
  TEST_ENV_DEPS := $(BUILD_DIR)/test-env-dump $(BUILD_DIR)/test-cat
endif

# Colors (used by test output)
GREEN  := \033[0;32m
BLUE   := \033[0;34m
CYAN   := \033[0;36m
YELLOW := \033[1;33m
RED    := \033[0;31m
RESET  := \033[0m

# Compiler flags
CFLAGS := -O2 -Wall -Wextra -Wpedantic \
          -Wshadow -Wstrict-prototypes -Wmissing-prototypes \
          -Wformat=2 -Wimplicit-fallthrough -Wundef \
          -Wnull-dereference -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)

# Warnings are errors, because this tree has none and the gates around it (the
# syscall coverage check, the EINTR contract, the proof targets) all fail the
# build rather than print. A compiler diagnostic that only prints is the one
# signal here that a reader has to notice on their own.
#
# WERROR=0 turns it off, which is what a newer compiler with a new warning
# wants: the flag must not be the reason a fresh clone stops building. CI keeps
# the default so the new warning still gets found.
WERROR ?= 1
ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

# Hardening. This process parses input the guest fully controls (its ELF, every
# syscall argument, FUSE frames, netlink messages, sockaddr and cmsg blobs), so
# the cheap compiler-side checks are worth their cost here even though the
# bounds math itself is proved in src/proved/. PIE is already the Darwin
# default; -fstack-protector-strong and _FORTIFY_SOURCE are not.
#
# _FORTIFY_SOURCE is skipped under AddressSanitizer alone, which predefines it
# to 0 on purpose (its interceptors do the same job), so redefining it is a
# -Wmacro-redefined error under the -Werror above. UBSAN and TSAN predefine
# nothing and keep it, which is what makes those lanes exercise the same libc
# entry points (__memcpy_chk and the rest) the shipped binary calls.
#
# Every -fsanitize= argument is split on commas so the test is an exact name
# match. A substring test for -fsanitize=address is order-dependent while
# reading as if it were not: it answers correctly for
# "-fsanitize=address,undefined" and wrongly for "-fsanitize=undefined,address",
# the same request spelled the other way round, which then fails the build on
# the macro redefinition.
sanitize_comma := ,
SANITIZERS := $(subst $(sanitize_comma), ,\
                $(patsubst -fsanitize=%,%,$(filter -fsanitize=%,$(CFLAGS))))

CFLAGS += -fstack-protector-strong
ifeq ($(filter address,$(SANITIZERS)),)
CFLAGS += -D_FORTIFY_SOURCE=2
endif

ifneq ($(strip $(ELFUSE_NR_EMBEDDER_HVC6)),)
CFLAGS += -DELFUSE_NR_EMBEDDER_HVC6=$(ELFUSE_NR_EMBEDDER_HVC6)
endif
