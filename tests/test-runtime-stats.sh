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
#   - summary mode prints the human vcpu-exit and histogram tables.
#
# Usage: tests/test-runtime-stats.sh <elfuse-binary> <static-guest-binary>
#
# The guest binary just needs to run briefly and exit cleanly; busybox
# (invoked as `sleep`/`true`) is the fixture the suite already ships.

set -u

ELFUSE="${1:?Usage: $0 <elfuse-binary> <static-guest-binary>}"
GUEST="${2:?Usage: $0 <elfuse-binary> <static-guest-binary>}"

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

# Count valid top-level JSON objects on stderr, ignoring any incidental
# non-JSON diagnostics (log_warn etc). Every stats object is emitted as one
# "{...}\n" line, so a line beginning with "{" is a candidate; it must parse
# or the whole check fails. Prints the count of valid objects, optionally
# filtered by reason; exits non-zero if a "{"-line does not parse as JSON.
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

# --- json mode: one valid object on a clean exit -------------------------
err="$tmpdir/json-clean.err"
ELFUSE_RUNTIME_STATS=json "$ELFUSE" "$GUEST" true 2> "$err" > /dev/null
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

# --- json mode: still one object when SIGUSR1 dumps are requested ---------
# Non-final (signal) dumps must be suppressed in json mode; otherwise the
# exit dump would append a second bare object and break the single-object
# contract. Spray signals across the sleep so at least one lands mid-run.
err="$tmpdir/json-signal.err"
ELFUSE_RUNTIME_STATS=json ELFUSE_STATS_SIGNAL=USR1 \
    "$ELFUSE" "$GUEST" sleep 1 2> "$err" > /dev/null &
pid=$!
for _ in 1 2 3 4; do
    sleep 0.15
    kill -USR1 "$pid" 2> /dev/null || true
done
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

# --- jsonl mode: every object line is standalone-valid --------------------
# The final dump guarantees one line; per-signal dumps must add at least one
# more when SIGUSR1 lands mid-run.
err="$tmpdir/jsonl.err"
ELFUSE_RUNTIME_STATS=jsonl ELFUSE_STATS_SIGNAL=USR1 \
    "$ELFUSE" "$GUEST" sleep 1 2> "$err" > /dev/null &
pid=$!
for _ in 1 2 3 4; do
    sleep 0.15
    kill -USR1 "$pid" 2> /dev/null || true
done
wait "$pid"
n="$(count_objs "$err")" || {
    die "jsonl mode: a line failed to parse as standalone JSON"
    cat "$err"
    n=0
}
s="$(count_objs "$err" signal)" || {
    die "jsonl mode: a line failed to parse as standalone JSON"
    cat "$err"
    s=0
}
if [ "$n" -gt 1 ] 2> /dev/null && [ "$s" -ge 1 ] 2> /dev/null; then
    pass "jsonl mode emits standalone-valid JSON objects ($n)"
else
    die "jsonl mode: missing SIGUSR1-triggered JSON object"
fi

# --- summary mode: human tables present ----------------------------------
err="$tmpdir/summary.err"
ELFUSE_RUNTIME_STATS=summary "$ELFUSE" "$GUEST" true 2> "$err" > /dev/null
if grep -q "vcpu-exit-stats" "$err" && grep -q "syscall histogram" "$err"; then
    pass "summary mode prints vcpu-exit and histogram tables"
else
    die "summary mode: missing vcpu-exit or histogram table"
    cat "$err"
fi

exit "$fail"
