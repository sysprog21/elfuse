#!/usr/bin/env bash

# Verify clang-format conformance for all tracked C/H files in src/ and
# tests/. The repository's .clang-format is calibrated against
# clang-format-22; older versions produce different output and are
# rejected to keep CI deterministic.

set -u -o pipefail

if [ -z "${CLANG_FORMAT:-}" ]; then
    if command -v clang-format-22 > /dev/null 2>&1; then
        CLANG_FORMAT="clang-format-22"
    elif command -v clang-format > /dev/null 2>&1; then
        # Allow the unversioned binary only if it reports v22.x.
        if clang-format --version 2> /dev/null | grep -qE 'version 22\.'; then
            CLANG_FORMAT="clang-format"
        else
            echo "Error: clang-format-22 is required (older versions differ in style)" >&2
            exit 1
        fi
    else
        echo "Error: clang-format-22 is required (older versions differ in style)" >&2
        exit 1
    fi
fi

ret=0
# The benchmark corpus is fixed input data. Formatting it would invalidate its
# performance baseline, so keep it out of the C source set.
while IFS= read -r -d '' file; do
    expected=$(mktemp)
    "$CLANG_FORMAT" "$file" > "$expected" 2> /dev/null
    if ! diff -u -p --label="$file" --label="expected coding style" "$file" "$expected"; then
        ret=1
    fi
    rm -f "$expected"
done < <(git ls-files -z -- 'src/*.c' 'src/*.h' 'src/**/*.c' 'src/**/*.h' \
    'tests/*.c' 'tests/*.h' ':(exclude)tests/bench-corpus/**')

exit $ret
