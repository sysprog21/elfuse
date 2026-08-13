# Project configuration

ENTITLEMENTS := entitlements.plist
SIGN_IDENTITY ?= -
BUILD_DIR := build
ELFUSE_BIN := $(BUILD_DIR)/elfuse
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
                tests/test-dynamic-array-host.c \
                tests/test-string-builder-host.c \
                tests/test-wakeup-pipe-host.c \
                tests/test-guest-env-host.c
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

ifneq ($(strip $(ELFUSE_NR_EMBEDDER_HVC6)),)
CFLAGS += -DELFUSE_NR_EMBEDDER_HVC6=$(ELFUSE_NR_EMBEDDER_HVC6)
endif
