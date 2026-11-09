#!/usr/bin/env bash

# Shared test limits derived from the runtime's capacity header.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Source this file from a test runner, or invoke it with --host-nofile to print
# the computed minimum for a Make recipe. Keeping the arithmetic here derived
# from src/elfuse-limits.h prevents shell and Make callers from drifting away
# from the values compiled into elfuse.

_test_config_script="${BASH_SOURCE[0]}"
_test_config_dir="$(cd "$(dirname "$_test_config_script")" && pwd)"
_test_config_root="$(cd "$_test_config_dir/.." && pwd)"
_test_config_header="$_test_config_root/src/elfuse-limits.h"

_test_config_define()
{
    local name="$1"
    awk -v wanted="$name" '$1 == "#define" && $2 == wanted { print $3; exit }' \
        "$_test_config_header"
}

ELFUSE_FD_TABLE_SIZE="$(_test_config_define FD_TABLE_SIZE)"
ELFUSE_HOST_FD_RESERVE="$(_test_config_define HOST_FD_RESERVE)"
if [ -z "$ELFUSE_FD_TABLE_SIZE" ] || [ -z "$ELFUSE_HOST_FD_RESERVE" ]; then
    echo "test-config: missing descriptor limits in $_test_config_header" >&2
    if [ "$_test_config_script" = "$0" ]; then
        exit 1
    fi
    return 1
fi

_test_config_default_host_nofile=$((ELFUSE_FD_TABLE_SIZE + ELFUSE_HOST_FD_RESERVE))
: "${ELFUSE_HOST_NOFILE_MIN:=$_test_config_default_host_nofile}"

export ELFUSE_FD_TABLE_SIZE ELFUSE_HOST_FD_RESERVE ELFUSE_HOST_NOFILE_MIN

# Resolve a manifest annotation such as host_nofile=elfuse-minimum. Numeric
# values are accepted for future tests that need a different explicit limit.
elfuse_resolve_host_nofile()
{
    local spec="${1:-}"
    case "$spec" in
        "")
            return 0
            ;;
        elfuse-minimum)
            printf '%s\n' "$ELFUSE_HOST_NOFILE_MIN"
            ;;
        *[!0-9]*)
            echo "test-config: unknown host_nofile annotation: $spec" >&2
            return 1
            ;;
        *)
            printf '%s\n' "$spec"
            ;;
    esac
}

# Read the host-limit annotation for a test from the manifest. The matrix runner
# and the data-driven driver therefore use the same metadata instead of growing
# independent name-qualified branches.
elfuse_test_host_nofile()
{
    local manifest="$1"
    local name
    name="$(basename -- "$2")"
    local spec
    spec=$(awk -v wanted="$name" '
        $1 == wanted {
            for (i = 2; i <= NF; i++) {
                if ($i ~ /^host_nofile=/) {
                    sub(/^host_nofile=/, "", $i)
                    print $i
                    exit
                }
            }
        }
    ' "$manifest")
    elfuse_resolve_host_nofile "$spec"
}

# A sourced configuration inherits the caller's positional parameters. Only
# inspect --host-nofile when this file itself is the executed script; otherwise
# a test runner whose first argument happens to match the CLI flag would emit an
# unexpected value while being initialized.
if [ "$_test_config_script" = "$0" ] \
    && [ "${1:-}" = "--host-nofile" ]; then
    printf '%s\n' "$ELFUSE_HOST_NOFILE_MIN"
fi
