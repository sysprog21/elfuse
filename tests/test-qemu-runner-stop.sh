#!/usr/bin/env bash

# test-qemu-runner-stop.sh -- Pin qemu-runner.sh stop against a state file
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Usage: tests/test-qemu-runner-stop.sh
#
# A state file outlives its VM, so the pid it records may since have been
# recycled by an unrelated process. stop --state-file has to leave such a
# process alone and still remove the record, and has to terminate a process
# whose argv names the run's own pidfile, as qemu's does. Both halves run
# against stand-ins, so no VM boots.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNNER="$SCRIPT_DIR/qemu-runner.sh"
# shellcheck source=tests/lib/report.sh
. "$SCRIPT_DIR/lib/report.sh"

work="$(mktemp -d)"
victims=()
cleanup()
{
    local p
    for p in ${victims[@]+"${victims[@]}"}; do
        kill "$p" 2> /dev/null || true
    done
    rm -rf "$work"
}
trap cleanup EXIT

# qemu_read_state accepts only the directory shape mktemp gives a run.
rundir="$work/elfuse-qemu.test"
pidfile="$rundir/qemu.pid"
state="$work/qemu.state"

arm()
{
    mkdir -p "$rundir"
    printf '%s\n' "$1" > "$pidfile"
    printf 'port=1\nkey=/dev/null\npidfile=%s\n' "$pidfile" > "$state"
}

check()
{
    local label="$1" want="$2" got="$3"
    if [ "$want" = "$got" ]; then
        report_pass "$label"
    else
        report_fail "$label (got $got, want $want)"
    fi
}

alive()
{
    kill -0 "$1" 2> /dev/null && echo alive || echo dead
}

present()
{
    [ -e "$1" ] && echo present || echo gone
}

# A recycled pid: a sleep whose argv never mentions the pidfile.
sleep 300 &
bystander=$!
victims+=("$bystander")
arm "$bystander"
rc=0
bash "$RUNNER" stop --state-file "$state" > /dev/null 2>&1 || rc=$?
check "stop returns 0 for a recycled pid" 0 "$rc"
check "a recycled pid survives stop" alive "$(alive "$bystander")"
check "stop removes the stale state file" gone "$(present "$state")"
check "stop removes the stale run directory" gone "$(present "$rundir")"

# The run's own process: its argv carries the pidfile, and it exits on TERM.
loop='trap "exit 0" TERM; while :; do sleep 1; done'
bash -c "$loop" bash -pidfile "$pidfile" &
own=$!
victims+=("$own")
arm "$own"
rc=0
bash "$RUNNER" stop --state-file "$state" > /dev/null 2>&1 || rc=$?
check "stop returns 0 for the run's own process" 0 "$rc"
check "the run's own process is terminated" dead "$(alive "$own")"
check "stop removes the state file after a kill" gone "$(present "$state")"

report_summary
[ "$fail" -eq 0 ]
