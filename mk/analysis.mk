# Static analysis and formatting

.PHONY: lint analyze check-format indent

CLANG_TIDY ?= clang-tidy

# Tracked source-like files only. Avoid editor/agent worktrees and other
# untracked mirrors under dot-directories.
C_FORMAT_FILES := $(shell git ls-files --cached --others --exclude-standard \
                           -- 'src/**/*.[ch]' 'src/*.[ch]' \
                           'tests/*.c' 'tests/*.h')
SHELL_SCRIPTS := $(shell git ls-files --cached --others --exclude-standard \
                         -- '*.sh')
PYTHON_FORMAT_FILES := $(shell git ls-files --cached --others --exclude-standard \
                              -- '*.py')

## Run clang-tidy on all source files. LIBARCHIVE_CFLAGS comes from the
## parent Makefile (pkg-config libarchive, keg-only) so src/oci/tar.c,
## which is the only translation unit that #includes <archive.h>, can
## resolve the header during analysis.
lint: $(BUILD_DIR)/shim_blob.h $(BUILD_DIR)/version.h
	@echo "  TIDY    src/"
	$(Q)$(CLANG_TIDY) $(SRCS) -- $(CFLAGS) -Isrc -I$(BUILD_DIR) \
	    $(LIBARCHIVE_CFLAGS)

## Run clang static analyzer (scan-build)
analyze:
	@echo "  SCAN    elfuse"
	$(Q)scan-build --use-cc=$(CC) $(MAKE) -B elfuse

## Check formatting: C (clang-format --dry-run) + shell (shellcheck)
check-format: check-syscall-dispatch
	@echo "  FMT     src/ tests/ (check)"
	$(Q)$(CLANG_FORMAT) --dry-run --Werror $(C_FORMAT_FILES)
	@printf "  SHCHK   %d scripts\n" $(words $(SHELL_SCRIPTS))
	@fail=0; \
	for f in $(SHELL_SCRIPTS); do \
		if shellcheck --severity=warning "$$f" 2>&1; then \
			printf "  $(GREEN)OK$(RESET) %s\n" "$$f"; \
		else \
			printf "  $(RED)FAIL$(RESET) %s\n" "$$f"; \
			fail=$$((fail + 1)); \
		fi; \
	done; \
	if [ "$$fail" -eq 0 ]; then \
		printf "$(GREEN)All %d scripts pass$(RESET)\n" $(words $(SHELL_SCRIPTS)); \
	else \
		printf "$(RED)%d script(s) have warnings$(RESET)\n" "$$fail"; \
		exit 1; \
	fi

## Indent all C, shell, and Python files in-place
indent: gen-syscall-dispatch
	@echo "  FMT     src/ tests/"
	$(Q)$(CLANG_FORMAT) -i $(C_FORMAT_FILES)
	@if command -v shfmt >/dev/null 2>&1; then \
		printf "  SHFMT   %d scripts\n" $(words $(SHELL_SCRIPTS)); \
		shfmt -w -ln=bash -i 4 -ci -bn -fn -sr $(SHELL_SCRIPTS); \
	fi
	@if command -v black >/dev/null 2>&1 && [ -n "$(PYTHON_FORMAT_FILES)" ]; then \
		printf "  BLACK   %d files\n" $(words $(PYTHON_FORMAT_FILES)); \
		black --quiet $(PYTHON_FORMAT_FILES); \
	fi
