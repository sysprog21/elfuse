# Shared reporting helpers for standalone test scripts.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck shell=bash
#
# Sources tests/lib/test-runner.sh and exposes report_pass / report_fail
# / report_skip on top of test_report so per-binary output matches the
# matrix runner's aarch64 format ([ OK ] / [ FAIL ] / [ SKIP ] aligned
# to TEST_LABEL_WIDTH). Each script still owns its pass/fail
# /skip/total counters; this lib only centralizes the report sites and
# the trailing Results: summary line that tests/test-matrix.sh scrapes.

# Align the LABEL column with tests/test-matrix.sh so the aggregated
# matrix output looks uniform across aarch64 and x86_64 modes.
: "${TEST_LABEL_WIDTH:=45}"

_report_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/lib/test-runner.sh
. "${_report_lib_dir}/test-runner.sh"

# report_pass / report_fail / report_skip accept a single label argument
# matching the original Rosetta helpers' single-string contract; the
# whole label (including any embedded "rc=..." detail) is shown in the
# LABEL column so existing call sites do not need a manual split.

report_pass()
{
    test_report ok "$1"
    pass=$((pass + 1))
}

report_fail()
{
    test_report fail "$1"
    fail=$((fail + 1))
}

report_skip()
{
    test_report skip "$1"
    skip=$((skip + 1))
}

# Emit the canonical Results line that tests/test-matrix.sh's
# suite_summary_fields regex consumes. Optional first argument
# overrides the (of N) field when the script tracks total
# independently of pass+fail+skip (the existing Rosetta scripts
# do, because in-script skips do not bump total).
report_summary()
{
    local total="${1:-$((pass + fail + skip))}"
    printf '\n'
    printf 'Results: %s passed, %s failed, %s skipped (of %s)\n' \
        "$pass" "$fail" "$skip" "$total"
}

# Locate timeout(1) on macOS hosts: not built in, but Homebrew coreutils
# ships it as 'timeout' (and the legacy 'gtimeout' alias). Sets the
# TIMEOUT shell variable in the caller. On failure, prints an install
# hint and exits 77 (suite-skip), matching what every per-script copy
# of this block used to do.
require_timeout()
{
    TIMEOUT="$(command -v timeout 2> /dev/null \
        || command -v gtimeout 2> /dev/null || true)"
    if [ -z "$TIMEOUT" ]; then
        printf 'timeout(1) not found in PATH; install via: brew install coreutils\n' >&2
        exit 77
    fi
}
