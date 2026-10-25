#!/usr/bin/env bash
# Helpers shared by the OCI CI lanes.
set -euo pipefail

fail()
{
    echo "FAIL: $*" >&2
    exit 1
}

# Drain stdin so pipefail does not report the producer's SIGPIPE.
expect_grep()
{
    grep -F -- "$1" > /dev/null
}

run_capture()
{
    local desc="$1" pattern="$2" out
    shift 2
    out="$("$@")" || fail "$desc: exited $?: $out"
    printf '%s: %s\n' "$desc" "$out"
    printf '%s\n' "$out" | expect_grep "$pattern" || fail "$desc: output lacks $pattern"
}

# Poll a predicate without letting its failures escape set -e.
wait_for()
{
    local timeout="$1" desc="$2" i=0
    shift 2
    while ! "$@" > /dev/null; do
        i=$((i + 1))
        [ "$i" -le $((timeout * 2)) ] || fail "timed out after ${timeout}s waiting for: $desc"
        sleep 0.5
    done
}
