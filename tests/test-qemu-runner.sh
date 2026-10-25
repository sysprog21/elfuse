#!/usr/bin/env bash

# test-qemu-runner.sh -- Pin qemu-runner.sh start and stop against stand-ins
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Usage: tests/test-qemu-runner.sh
#
# No VM boots here: a stub stands in for qemu. stop must leave a recycled pid
# alone yet terminate a process whose argv names the run's pidfile, and a failed
# start must report what the VM said before its run directory goes.

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

fake_start()
{
    mkdir -p "$rundir"
    printf '%s\n' "$1" > "$pidfile"
    printf 'port=1\nkey=/dev/null\npidfile=%s\n' "$pidfile" > "$state"
}

dead()
{
    ! kill -0 "$1" 2> /dev/null
}

# A recycled pid: a sleep whose argv never mentions the pidfile.
sleep 300 &
bystander=$!
victims+=("$bystander")
fake_start "$bystander"
check_host "stop returns 0 for a recycled pid" bash "$RUNNER" stop --state-file "$state"
check_host "a recycled pid survives stop" kill -0 "$bystander"
check_host "stop removes the stale state file" test ! -e "$state"
check_host "stop removes the stale run directory" test ! -e "$rundir"

# A state file that names a directory outside a run through "..".
victim="$work/victim"
mkdir -p "$rundir" "$victim"
printf 'pidfile=%s/../victim/qemu.pid\n' "$rundir" > "$state"
rc=0
bash "$RUNNER" stop --state-file "$state" 2> /dev/null || rc=$?
check_host "stop rejects a pidfile outside a run directory" test "$rc" -eq 1
check_host "the directory a rejected state file names survives" test -d "$victim"

# The run's own process: its argv carries the pidfile, and it exits on TERM.
loop='trap "exit 0" TERM; while :; do sleep 1; done'
bash -c "$loop" bash -pidfile "$pidfile" &
own=$!
victims+=("$own")
fake_start "$own"
check_host "stop returns 0 for the run's own process" bash "$RUNNER" stop --state-file "$state"
check_host "the run's own process is terminated" dead "$own"
check_host "stop removes the state file after a kill" test ! -e "$state"

# A failed start: a stub qemu that never opens the port.
stub="$work/qemu-stub"
cat > "$stub" << 'STUB'
#!/usr/bin/env bash
serial=""
while [ $# -gt 0 ]; do
    [ "$1" = -serial ] && serial="${2#file:}"
    [ "$1" = -pidfile ] && echo "$2" > "$(dirname "$0")/pidfile-arg"
    shift
done
[ -z "$serial" ] || echo SERIAL-MARKER > "$serial"
echo STDERR-MARKER >&2
STUB
chmod +x "$stub"
fixture="$work/fixture"
echo fixture > "$fixture"
rm -f "$state"
rc=0
out="$(QEMU_BIN="$stub" QEMU_ACCEL=tcg QEMU_BOOT_TIMEOUT=1 \
    QEMU_KERNEL="$fixture" QEMU_INITRD="$fixture" QEMU_SSH_KEY="$fixture" \
    bash "$RUNNER" start --state-file "$state" 2>&1)" || rc=$?
check_host "start fails when the VM never boots" test "$rc" -eq 1
check_host "the failure names the timeout" grep -qF "did not boot" <<< "$out"
check_host "the serial console reaches the caller" grep -qF SERIAL-MARKER <<< "$out"
check_host "qemu's own output reaches the caller" grep -qF STDERR-MARKER <<< "$out"
check_host "a failed start writes no state file" test ! -e "$state"
failed_rundir="$(dirname "$(cat "$work/pidfile-arg")")"
check_host "a failed start removes its run directory" test ! -e "$failed_rundir"

report_summary
[ "$fail" -eq 0 ]
