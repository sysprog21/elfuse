#!/usr/bin/env bash
# Runtime-stats subsystem smoke test (ELFUSE_RUNTIME_STATS)
#
# Guards the runtime-stats output paths that have no other coverage:
#   - json mode emits exactly one valid top-level JSON object on exit,
#     even when SIGUSR1 dumps are requested mid-run. This is the guard
#     against the "two bare JSON objects on stderr is not valid JSON"
#     regression: a conforming parser must accept the whole stderr.
#   - jsonl mode emits one valid JSON object per line and honors the
#     on-demand SIGUSR1 dump, so a mid-run signal adds a line.
#   - a fork child closes its own window with a final record.
#   - ELFUSE_STATS_SIGNAL leaves SIGUSR1 alone while stats are off.
#   - scripts/runtime-stats-convert.py passes its self-checks.
#   - summary mode prints the human vcpu-exit and histogram tables.
#
# Usage: tests/test-runtime-stats.sh <elfuse-binary> <static-guest-binary>
#
# The guest binary just needs to run briefly and exit cleanly; busybox (invoked
# as `sleep`/`true`) is the fixture the suite already ships.

set -u

ELFUSE="${1:?Usage: $0 <elfuse-binary> <static-guest-binary>}"
GUEST="${2:?Usage: $0 <elfuse-binary> <static-guest-binary>}"

# The guest shell runs applets by exec, and a busybox built without standalone
# applets resolves "sleep" through PATH to the host's own binary. Name the
# fixture by absolute path so the shell can exec it as itself.
GUEST="$(cd "$(dirname "$GUEST")" && pwd)/$(basename "$GUEST")"

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
RESET=$'\033[0m'

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

fail=0
pass()
{
    printf "%sPASS%s %s\n" "$GREEN" "$RESET" "$1"
}
die()
{
    printf "%sFAIL%s %s\n" "$RED" "$RESET" "$1"
    fail=1
}

# Count valid top-level JSON objects on stderr, ignoring any incidental non-JSON
# diagnostics (log_warn etc). Every stats object is emitted as one "{...}\n"
# line, so a line beginning with "{" is a candidate; it must parse or the whole
# check fails. Prints the count of valid objects, optionally filtered by reason;
# exits non-zero if a "{"-line does not parse as JSON.
count_objs()
{
    python3 - "$@" << 'PY'
import json, sys
n = 0
want_reason = sys.argv[2] if len(sys.argv) > 2 else None
for line in open(sys.argv[1]):
    if not line.lstrip().startswith("{"):
        continue
    obj = json.loads(line)  # raises -> non-zero exit -> caller treats as failure
    if want_reason is not None and obj.get("reason") != want_reason:
        continue
    n += 1
print(n)
PY
}

# Send SIGUSR1 a few times once the guest has printed "ready". A guest that runs
# has been attached, so every request lands; one sent earlier would be dropped,
# or kill elfuse outright before it claims the signal.
signal_when_ready()
{
    local pid="$1" out="$2"
    for _ in $(seq 1 100); do
        grep -q ready "$out" 2> /dev/null && break
        sleep 0.05
    done
    for _ in 1 2 3; do
        kill -USR1 "$pid" 2> /dev/null || true
        sleep 0.1
    done
}

# json mode: one valid object on a clean exit
err="$tmpdir/json-clean.err"
ELFUSE_RUNTIME_STATS=json "$ELFUSE" "$GUEST" true 2> "$err" > /dev/null
rc=$?
[ "$rc" -eq 0 ] || die "json mode: guest exited $rc"
n="$(count_objs "$err")" || {
    die "json mode: a JSON line failed to parse"
    cat "$err"
    n=x
}
if [ "$n" = "1" ]; then
    pass "json mode emits one valid JSON object on exit"
elif [ "$n" != "x" ]; then
    die "json mode: expected exactly 1 JSON object, got $n"
fi

# json mode: still one object when SIGUSR1 dumps are requested Non-final
# (signal) dumps must be suppressed in json mode; otherwise the exit dump would
# append a second bare object and break the single-object contract. Spray
# signals across the sleep so at least one lands mid-run.
err="$tmpdir/json-signal.err"
ELFUSE_RUNTIME_STATS=json ELFUSE_STATS_SIGNAL=USR1 \
    "$ELFUSE" "$GUEST" sh -c 'echo ready; exec "$0" sleep 1' "$GUEST" 2> "$err" \
    > "$tmpdir/json-signal.out" &
pid=$!
signal_when_ready "$pid" "$tmpdir/json-signal.out"
wait "$pid"
n="$(count_objs "$err")" || {
    die "json+SIGUSR1: a JSON line failed to parse"
    cat "$err"
    n=x
}
if [ "$n" = "1" ]; then
    pass "json mode suppresses signal dumps (one object under SIGUSR1)"
elif [ "$n" != "x" ]; then
    die "json mode + SIGUSR1: signal dumps leaked extra objects ($n)"
fi

# jsonl mode: every object line is standalone-valid The final dump guarantees
# one line; per-signal dumps must add at least one more when SIGUSR1 lands
# mid-run.
err="$tmpdir/jsonl.err"
ELFUSE_RUNTIME_STATS=jsonl ELFUSE_STATS_SIGNAL=USR1 \
    "$ELFUSE" "$GUEST" sh -c 'echo ready; exec "$0" sleep 1' "$GUEST" 2> "$err" \
    > "$tmpdir/jsonl.out" &
pid=$!
signal_when_ready "$pid" "$tmpdir/jsonl.out"
wait "$pid"
rc=$?
e="$(count_objs "$err" exit)" || e=x
s="$(count_objs "$err" signal)" || s=x
if [ "$rc" -eq 0 ] && [ "$e" = "1" ] && [ "$s" -ge 1 ] 2> /dev/null; then
    pass "jsonl mode emits one exit record and $s snapshot(s)"
else
    die "jsonl mode: rc=$rc exit records=$e snapshots=$s"
    cat "$err"
fi

# Fork children: each process emits its own final record. A backgrounded
# subshell is a fork child; it must close its own window with a final record
# instead of vanishing from the accounting.
err="$tmpdir/jsonl-fork.err"
ELFUSE_RUNTIME_STATS=jsonl "$ELFUSE" "$GUEST" sh -c 'true & wait' \
    2> "$err" > /dev/null
n="$(count_objs "$err" fork-child-exit)" || n=x
if [ "$n" -ge 1 ] 2> /dev/null; then
    pass "fork child emits its own final record"
else
    die "fork child: no fork-child-exit record ($n)"
    cat "$err"
fi

# the snapshot signal is claimed only while stats are on With
# ELFUSE_STATS_SIGNAL set but stats off, SIGUSR1 keeps its default action and
# terminates elfuse, as it would any other process. The probe waits for the
# guest so the signal lands after bring-up, where a wrongly claimed SIGUSR1
# would be swallowed rather than kill the process.
ELFUSE_RUNTIME_STATS=0 ELFUSE_SHIM_STATS=0 ELFUSE_STATS_SIGNAL=USR1 \
    "$ELFUSE" "$GUEST" sh -c 'echo ready; exec "$0" sleep 5' "$GUEST" \
    2> /dev/null > "$tmpdir/off.out" &
pid=$!
for _ in $(seq 1 100); do
    grep -q ready "$tmpdir/off.out" 2> /dev/null && break
    sleep 0.05
done
kill -USR1 "$pid" 2> /dev/null || true
wait "$pid" 2> /dev/null
rc=$?
want=$((128 + $(kill -l USR1)))
if [ "$rc" -eq "$want" ]; then
    pass "SIGUSR1 keeps its default action with stats off"
else
    die "SIGUSR1 with stats off: expected exit $want, got $rc"
fi

# converter self-checks
convert="$(dirname "$0")/../scripts/runtime-stats-convert.py"
for fmt in csv folded speedscope perfetto; do
    if python3 "$convert" --selftest "$fmt"; then
        pass "runtime-stats-convert.py $fmt self-check"
    else
        die "runtime-stats-convert.py $fmt self-check"
    fi
done

# summary mode: human tables present
err="$tmpdir/summary.err"
ELFUSE_RUNTIME_STATS=summary "$ELFUSE" "$GUEST" true 2> "$err" > /dev/null
if grep -q "vcpu-exit-stats" "$err" && grep -q "syscall histogram" "$err"; then
    pass "summary mode prints vcpu-exit and histogram tables"
else
    die "summary mode: missing vcpu-exit or histogram table"
    cat "$err"
fi

exit "$fail"
