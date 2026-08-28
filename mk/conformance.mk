.PHONY: test-conformance-harness test-conformance test-conformance-full \
        conformance-payloads clean-payloads update-pins

CONFORMANCE := python3 scripts/conformance
CONF_SUITES :=
BACKEND ?= elfuse
TEST ?=
CONF_JOBS ?= 4
CONF_RESULTS ?= $(BUILD_DIR)/conformance
CONF_RUN = $(CONFORMANCE) --backend $(BACKEND) --jobs $(CONF_JOBS) --results $(CONF_RESULTS)
CONF_SCOPE ?= pr
CONF_RUN_SCOPE = $(if $(TEST),test $(TEST),$(CONF_SCOPE))
# foreach inserts spaces, but RUN_OPTIONAL_SKIP77 expands as a recipe line.
define conf-newline


endef

## Run the conformance harness selftests (hermetic)
test-conformance-harness:
	@$(CONFORMANCE) selftest

## Run every suite's CONF_SCOPE (pr) subset, or TEST=ID... (BACKEND=elfuse|qemu|all|host)
test-conformance:
	$(if $(CONF_SUITES),,@printf "$(YELLOW)SKIP$(RESET) no conformance suites registered\n")
	$(foreach s,$(CONF_SUITES),$(call RUN_OPTIONAL_SKIP77,$(CONF_RUN) $(s) $(CONF_RUN_SCOPE),test-$(s))$(conf-newline))

## Run every suite in full, the nightly shape
test-conformance-full:
	$(if $(CONF_SUITES),,@printf "$(YELLOW)SKIP$(RESET) no conformance suites registered\n")
	$(foreach s,$(CONF_SUITES),$(call RUN_OPTIONAL_SKIP77,$(CONF_RUN) $(s) full,test-$(s)-full)$(conf-newline))

## Build every conformance payload under externals/payloads/
conformance-payloads:
	$(if $(CONF_SUITES),,@printf "$(YELLOW)SKIP$(RESET) no conformance suites registered\n")
	$(foreach s,$(CONF_SUITES),$(CONFORMANCE) $(s) payload &&) true

## Remove the conformance payloads (they survive clean and distclean)
clean-payloads:
	rm -rf externals/payloads

UPDATE_CHECK ?=

## Refresh the conformance pins from upstream (UPDATE_CHECK=1 to report only)
update-pins:
	$(if $(CONF_SUITES),,@printf "$(YELLOW)SKIP$(RESET) no conformance suites registered\n")
	$(foreach s,$(CONF_SUITES),$(CONFORMANCE) $(s) update $(if $(UPDATE_CHECK),--check) $(if $(CONF_REF_$(s)),--ref $(CONF_REF_$(s))) &&) true
