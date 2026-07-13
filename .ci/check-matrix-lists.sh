#!/usr/bin/env bash

# Keep the test-matrix skip lists honest.
#
# tests/test-matrix.sh runs each test under two runners and carries a skip list
# per runner: QEMU_SKIP for tests the reference kernel cannot adjudicate,
# ELFUSE_SKIP for tests that need a writable byte-exact root the elfuse lane
# does not have. Both lists are matched against a test's label by string, and a
# string that matches nothing fails silently: the suite still reports success,
# having run one test fewer than the reader believes.
#
# Two ways that goes wrong, both of which cost coverage without costing a red
# build, and neither of which the suite itself can notice:
#
#   1. A label in a skip list that no longer names a registered test. Dead
#      config: it reads as deliberate coverage policy while guarding nothing,
#      and it hides the rename that orphaned it.
#   2. A label in both lists at once. The test is then skipped under every
#      runner the matrix has, so it never executes anywhere while still looking
#      registered.
#   3. A tests/manifest.txt binary that no test_* call registers at all. Same
#      cost, arrived at from the other side: "make check" runs it, the matrix
#      never does, and the reference kernel therefore never adjudicates it. Six
#      tests reached that state before this check existed, four of them added
#      in the same branch that claimed they encoded Linux behaviour. Only the
#      matrix can substantiate such a claim, so a test that skips it is a claim
#      nobody checked.
#
# The pass counts themselves are not checked here. test-matrix.sh already holds
# each lane to its EXPECTED_BASELINES floor at runtime, which is a stronger
# check than anything static, and duplicating it would only add a second number
# to keep in step.

set -e -u -o pipefail

MATRIX="${1:-$(dirname "$0")/../tests/test-matrix.sh}"

if [ ! -r "$MATRIX" ]; then
    echo "check-matrix-lists: cannot read $MATRIX" >&2
    exit 2
fi

# Body of a NAME="..." block spanning lines, one entry per line.
list_entries()
{
    sed -n "/^$1=\"/,/^\"\$/p" "$MATRIX" | sed '1d;$d' | tr -s ' \t' '\n' \
        | grep -v '^$' || true
}

# Labels registered with the test_* wrappers: the argument after "$runner".
registered_labels()
{
    grep -oE '\btest_(check|rc|pipe) +"\$runner" +"[^"]+"' "$MATRIX" \
        | sed -E 's/.*"\$runner" +"([^"]+)"$/\1/' | sort -u
}

# Manifest binaries the matrix deliberately does not run. Each asserts an
# elfuse-internal implementation detail with no counterpart on a real kernel, so
# the reference lane has nothing to say about it. The matrix's own comment above
# its suite list is the long form; this is the machine-readable copy.
MATRIX_EXEMPT="
test-oom-proc
test-shim-identity
test-shim-identity-attention
test-shim-verbose-trace
test-shim-data-el1
test-shim-urandom-smp
test-shim-urandom-toctou
test-shim-urandom-wrap
test-shim-cred-race
test-mmap-fastpath
test-mremap-infra
test-mremap-fork-tracking
test-dev-shm-paths
"

# The binary name from each manifest line: the first field, with any trailing
# arguments and any "#" marker dropped.
#
# Matching the whole line instead missed 17 of the 84 entries, because a
# manifest line carries arguments (test-argc a b c) and markers (test-thread #
# diff=skip) beside the name. Those were exactly the entries a coverage guard
# most wants to see, and it reported success while checking two thirds of the
# list.
manifest_tests()
{
    local manifest
    manifest="$(dirname "$0")/../tests/manifest.txt"
    if [ ! -r "$manifest" ]; then
        echo "Error: cannot read $manifest; the coverage check needs it" >&2
        return 1
    fi
    sed -E 's/#.*//' "$manifest" | awk '{print $1}' \
        | grep -E '^test-[A-Za-z0-9._-]+$' | sort -u
}

ret=0
registered="$(registered_labels)"

manifest_list="$(manifest_tests)" || exit 1

while IFS= read -r test; do
    [ -n "$test" ] || continue
    printf '%s\n' "$MATRIX_EXEMPT" | grep -qxF "$test" && continue
    if ! printf '%s\n' "$registered" | grep -qxF "$test"; then
        echo "Error: tests/manifest.txt has '$test', which the matrix never runs." >&2
        echo "       Add a test_* call for it, or name it in MATRIX_EXEMPT here" >&2
        echo "       with the reason the reference kernel cannot adjudicate it." >&2
        ret=1
    fi
done <<< "$manifest_list"

for list in QEMU_SKIP ELFUSE_SKIP; do
    while IFS= read -r label; do
        [ -n "$label" ] || continue
        if ! printf '%s\n' "$registered" | grep -qxF "$label"; then
            echo "Error: $list names '$label', which no test_* call registers" >&2
            ret=1
        fi
    done < <(list_entries "$list")
done

while IFS= read -r label; do
    [ -n "$label" ] || continue
    if list_entries QEMU_SKIP | grep -qxF "$label"; then
        echo "Error: '$label' is in both QEMU_SKIP and ELFUSE_SKIP, so it never runs" >&2
        ret=1
    fi
done < <(list_entries ELFUSE_SKIP)

exit $ret
