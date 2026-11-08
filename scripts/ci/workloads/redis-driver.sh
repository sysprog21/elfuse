# shellcheck shell=sh
# Drive BGSAVE from a second guest while redis-server runs in the first.
set -e
port="$1"

r()
{
    redis-cli -h 127.0.0.1 -p "$port" "$@"
}

# redis-cli exits 0 for an error reply, so compare every response.
out=$(r PING)
if [ "$out" != PONG ]; then
    echo "PING returned '$out'" >&2
    exit 1
fi

out=$(r SET elfuse:workload elfuse-redis-value)
if [ "$out" != OK ]; then
    echo "SET returned '$out'" >&2
    exit 1
fi

out=$(r GET elfuse:workload)
if [ "$out" != elfuse-redis-value ]; then
    echo "GET returned '$out'" >&2
    exit 1
fi

# rdb_last_bgsave_status starts at ok, so also wait for this save to finish.
out=$(r BGSAVE)
if [ "$out" != "Background saving started" ]; then
    echo "BGSAVE returned '$out'" >&2
    exit 1
fi

# INFO lines end in \r\n, so substring greps only, never full-line matches.
i=0
while [ "$i" -lt 30 ]; do
    if r INFO persistence | grep -q 'rdb_bgsave_in_progress:0'; then
        break
    fi
    sleep 1
    i=$((i + 1))
done

# Do not let the loop timeout fall through to the boot-time ok status.
info="$(r INFO persistence)"
if ! printf '%s' "$info" | grep -q 'rdb_bgsave_in_progress:0'; then
    printf '%s\n' "$info" >&2
    echo "BGSAVE still in progress after 30s" >&2
    exit 1
fi
if ! printf '%s' "$info" | grep -q 'rdb_last_bgsave_status:ok'; then
    printf '%s\n' "$info" >&2
    echo "BGSAVE did not finish with status ok" >&2
    exit 1
fi

echo "elfuse-oci-redis-workload-ok"

r SHUTDOWN NOSAVE || true
