#!/usr/bin/env bash

# Verify clang-format conformance for all tracked C/H files in src/ and tests/.
# The repository's .clang-format is calibrated against clang-format-22; older
# versions produce different output and are rejected to keep CI deterministic.
#
# Exit codes, matching .ci/check-commentflow.sh: 0 clean, 1 files differ from
# the style, 2 the check could not run. The split matters to the pre-commit
# hook, which blocks on 1 and only warns on 2: a machine without the pinned
# formatter has not shown you a defect, and turning that into a failed commit
# teaches contributors to pass --no-verify. CI fails on either.

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
            exit 2
        fi
    else
        echo "Error: clang-format-22 is required (older versions differ in style)" >&2
        exit 2
    fi
fi

# Named paths win over the tracked set, so the pre-commit hook can point this at
# an extracted index and get the same version gate and the same diff applied to
# staged content instead of carrying its own copy of both.
list_files()
{
    if [ "$#" -gt 0 ]; then
        printf '%s\0' "$@"
    else
        git ls-files -z -- 'src/*.c' 'src/*.h' 'src/**/*.c' 'src/**/*.h' \
            'tests/*.c' 'tests/*.h' ':(exclude)tests/bench-corpus/**'
    fi
}

# Kept apart, because the two answers have different consequences and one of
# them must not be able to mask the other. A file that differs is a defect in
# the change and blocks; a file the formatter could not read or parse is not,
# and reporting it as a style violation sends the author to reformat code that
# was already fine. A named path that does not exist reached the diff below and
# came back as "this file differs" in its entirety, which is the mistyped-path
# case .ci/check-security.sh guards against by name.
differ=0
unusable=0
while IFS= read -r -d '' file; do
    if [ ! -r "$file" ]; then
        echo "Cannot read $file" >&2
        unusable=1
        continue
    fi
    expected=$(mktemp)
    if ! "$CLANG_FORMAT" "$file" > "$expected"; then
        echo "Error: $CLANG_FORMAT failed on $file" >&2
        unusable=1
        rm -f "$expected"
        continue
    fi
    if ! diff -u -p --label="$file" --label="expected coding style" "$file" "$expected"; then
        differ=1
    fi
    rm -f "$expected"
done < <(list_files "$@")

[ "$differ" -eq 0 ] || exit 1
[ "$unusable" -eq 0 ] || exit 2
exit 0
