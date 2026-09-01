.PHONY: test-conformance-harness test-conformance test-conformance-full \
        conformance-payloads clean-payloads update-pins

CONFORMANCE := python3 scripts/conformance
# The suite registry lives in tests/conformance/providers/__init__.py. On a
# failed discovery the marker fails every consumer instead of skipping.
CONF_SUITES ?= $(shell $(CONFORMANCE) suites || echo suite-discovery-failed)
BACKEND ?= elfuse
TEST ?=
CONF_JOBS ?= 4
CONF_RESULTS ?= $(BUILD_DIR)/conformance
CONF_RUN = $(CONFORMANCE) run
CONF_SCOPE ?= pr
CONF_SELECT = $(if $(TEST),$(foreach id,$(TEST),--case '$(id)'),--scope $(CONF_SCOPE))
CONF_NO_SUITES = $(if $(CONF_SUITES),,@printf "$(YELLOW)SKIP$(RESET) no conformance suites registered\n")
# foreach inserts spaces, but RUN_OPTIONAL_SKIP77 expands as a recipe line.
define conf-newline


endef
define conf-lane
$(foreach s,$(CONF_SUITES),$(call RUN_OPTIONAL_SKIP77,$(CONF_RUN) $(s) $(1) --backend $(BACKEND) --jobs $(CONF_JOBS) --results $(CONF_RESULTS),test-$(s)$(2))$(conf-newline))
endef

## Run the conformance harness selftests (hermetic)
test-conformance-harness:
	@$(CONFORMANCE) selftest

## Run every suite's CONF_SCOPE subset, or TEST=ID... (BACKEND=elfuse|qemu|all)
test-conformance:
	$(CONF_NO_SUITES)
	$(call conf-lane,$(CONF_SELECT),)

## Run every suite in full, the nightly shape
test-conformance-full:
	$(CONF_NO_SUITES)
	$(call conf-lane,--scope full,-full)

## Build every conformance payload under externals/payloads/
conformance-payloads:
	$(CONF_NO_SUITES)
	$(foreach s,$(CONF_SUITES),$(CONFORMANCE) payload build $(s) &&) true

## Remove the conformance payloads (they survive clean and distclean)
clean-payloads:
	rm -rf externals/payloads

UPDATE_CHECK ?=

## Refresh the conformance pins from upstream (UPDATE_CHECK=1 to report only)
update-pins:
	$(CONF_NO_SUITES)
	$(foreach s,$(CONF_SUITES),$(CONFORMANCE) pins $(if $(filter 1,$(UPDATE_CHECK)),check,update) $(s) $(if $(CONF_REF_$(s)),--ref $(CONF_REF_$(s))) &&) true
