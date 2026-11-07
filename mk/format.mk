# Source formatting

.PHONY: check-format indent

# Tracked source-like files only. Avoid editor/agent worktrees and other
# untracked mirrors under dot-directories.
C_FORMAT_FILES := $(shell git ls-files --cached --others --exclude-standard \
                           -- 'src/**/*.[ch]' 'src/*.[ch]' \
                           'tests/*.c' 'tests/*.h' \
                           'frama-c-stubs/**/*.h' 'frama-c-stubs/*.h' \
                           ':(exclude)tests/bench-corpus/**')
SHELL_SCRIPTS := $(shell git ls-files --cached --others --exclude-standard \
                         -- '*.sh')
PYTHON_FORMAT_FILES := $(shell git ls-files --cached --others \
                               --exclude-standard -- '*.py')

# Comment reflow. clang-format breaks an over-long comment line but never
# refills a short-wrapped one, so commentflow settles comment width and runs
# first; clang-format then normalizes the indentation it produced. Required
# rather than best-effort, unlike shfmt and black below: a run that skips it
# formats to a different standard than the last one did.
#
# .ci/check-commentflow.sh holds the file list for both this target and the
# gate, so the set rewritten is the set checked.
COMMENTFLOW ?= commentflow

## Check formatting: comments (commentflow) + C (clang-format --dry-run) + shell (shellcheck)
check-format: check-syscall-dispatch
	$(Q)COMMENTFLOW=$(COMMENTFLOW) bash .ci/check-commentflow.sh
	@echo "  FMT     src/ tests/ (check)"
	$(Q)$(CLANG_FORMAT) --dry-run --Werror $(C_FORMAT_FILES)
	@echo "  MATRIX  skip lists"
	$(Q)bash .ci/check-matrix-lists.sh
	$(call require-tool,shellcheck,brew install shellcheck)
	@# -x follows the "# shellcheck source=..." directives the scripts already
	@# carry. Without it those directives are inert, every variable a sourced
	@# lib sets reads as unassigned, and the counters in tests/lib/report.sh
	@# had to be duplicated into each of its twelve callers to keep the gate
	@# quiet -- which then failed the other way, as twelve assignments nobody
	@# in that file uses.
	@printf "  SHCHK   %d scripts\n" $(words $(SHELL_SCRIPTS))
	@fail=0; \
	for f in $(SHELL_SCRIPTS); do \
		if shellcheck -x --severity=warning "$$f" 2>&1; then \
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
#
# shfmt and black are opt-in, unlike clang-format and commentflow. Those two are
# pinned (LINT_PKGS in .github/workflows/lint.yml, and commentflow by checksum)
# and check-format verifies what they write, so running them is idempotent
# against the tree. shfmt and black are neither pinned nor checked: CI installs
# shellcheck, which lints shell but does not format it, and nothing looks at
# Python formatting at all. Their output tracks whichever version the developer
# happens to have, so running them unconditionally rewrites files no gate asked
# to change. Measured on shfmt 3.14.0 and black 26.5.1 against cfc696e: one
# shell script and one Python script, both of which check-format accepts either
# way, landing as unrelated churn in whatever diff was open.
#
# Set FORMAT_SHELL=1 / FORMAT_PY=1 to run them anyway. The other way out is to
# pin both in the workflow and add shfmt -l / black --check to check-format,
# which makes the pair inverse; that is a CI change and it has to land with the
# reformat it implies.
indent: gen-syscall-dispatch
	$(Q)COMMENTFLOW=$(COMMENTFLOW) bash .ci/check-commentflow.sh --write
	@echo "  FMT     src/ tests/"
	$(Q)$(CLANG_FORMAT) -i $(C_FORMAT_FILES)
	@if [ -n "$(FORMAT_SHELL)" ] && command -v shfmt >/dev/null 2>&1; then \
		printf "  SHFMT   %d scripts\n" $(words $(SHELL_SCRIPTS)); \
		shfmt -w -ln=bash -i 4 -ci -bn -fn -sr $(SHELL_SCRIPTS); \
	fi
	@if [ -n "$(FORMAT_PY)" ] && command -v black >/dev/null 2>&1 && [ -n "$(PYTHON_FORMAT_FILES)" ]; then \
		printf "  BLACK   %d files\n" $(words $(PYTHON_FORMAT_FILES)); \
		black --quiet $(PYTHON_FORMAT_FILES); \
	fi
