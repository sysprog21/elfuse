# EL1 kernel shim pipeline
#
# shim.S + freestanding shim-mmap.c -> shim.o -> shim.bin -> shim_blob.h

SHIM_CFLAGS := -O2 -Wall -Wextra -Wpedantic -Wshadow \
	-Wstrict-prototypes -Wmissing-prototypes -Wformat=2 \
	-Wimplicit-fallthrough -Wundef -Wnull-dereference \
	-Wno-unused-parameter -ffreestanding -fno-builtin \
	-fno-stack-protector -fno-unwind-tables \
	-fno-asynchronous-unwind-tables -mno-outline-atomics
SHIM_LD ?= ld

$(BUILD_DIR)/shim-asm.o: src/core/shim.S | $(BUILD_DIR)
	@echo "  AS      $<"
	$(Q)$(SHIM_AS) $(SHIM_ASFLAGS) -o $@ $<

$(BUILD_DIR)/shim-mmap.o: src/core/shim-mmap.c src/core/shim-mmap.h \
		src/core/mmap-fastpath.h src/core/shim-globals.h | $(BUILD_DIR)
	@echo "  CC      $<"
	$(Q)$(CC) $(SHIM_CFLAGS) -MMD -MP -MF $(BUILD_DIR)/shim-mmap.d \
		-Isrc -c -o $@ $<

$(BUILD_DIR)/shim.o: $(BUILD_DIR)/shim-asm.o $(BUILD_DIR)/shim-mmap.o
	@echo "  LD      $@"
	$(Q)$(SHIM_LD) -static -arch arm64 -e _start -o $@ $^

$(BUILD_DIR)/shim.bin: $(BUILD_DIR)/shim.o
	@echo "  OBJCOPY $@"
	$(Q)$(OBJCOPY) -O binary $< $@
	$(Q)magic=$$(od -An -N4 -tx1 $@ | tr -d '[:space:]'); \
	case "$$magic" in \
	cffaedfe|cefaedfe|feedface|feedfacf|cafebabe|bebafeca|cafebabf|bfbafeca) \
	  echo "ERROR: $@ still has a Mach-O header (magic $$magic)."; \
	  echo "       $(OBJCOPY) does not strip Mach-O containers in -O binary mode."; \
	  echo "       Install GNU binutils (brew install binutils) and rebuild, or"; \
	  echo "       set OBJCOPY=/opt/homebrew/opt/binutils/bin/objcopy."; \
	  rm -f $@; exit 1;; \
	esac

$(BUILD_DIR)/shim_blob.h: $(BUILD_DIR)/shim.bin
	@echo "  GEN     $@"
	$(Q)tmp="$@.$$$$.tmp"; \
	xxd -i $< | \
		sed -e 's/unsigned char .*\[\]/static const unsigned char shim_bin[]/' \
		    -e 's/unsigned int .*_len/static const unsigned int shim_bin_len/' > "$$tmp"; \
	cmp -s "$$tmp" "$@" 2>/dev/null || mv "$$tmp" "$@"; \
	rm -f "$$tmp"

# Version header -- regenerates when HEAD or index changes.
# cmp trick avoids unnecessary rebuilds when version string is unchanged.
VERSION_DEPS := $(wildcard .git/HEAD .git/index) mk/config.mk
$(BUILD_DIR)/version.h: $(VERSION_DEPS) | $(BUILD_DIR)
	$(Q)mkdir -p $(dir $@)
	$(Q)tmp="$@.$$$$.tmp"; \
	printf '#define ELFUSE_VERSION "%s"\n' "$(VERSION)" > "$$tmp"; \
	cmp -s "$$tmp" "$@" 2>/dev/null || mv "$$tmp" "$@"; \
	rm -f "$$tmp"
