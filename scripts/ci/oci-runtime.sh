#!/usr/bin/env bash
# Run one elfuse runtime lane on an OCI image and require its sentinel. The keys
# are the case arms below and the oci-runtime matrix in build.yml. Usage:
# ELFUSE_OCI_STORE=<store> scripts/ci/oci-runtime.sh <key>
# shellcheck source=scripts/ci/oci-lib.sh
. "$(dirname "$0")/oci-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/scripts/elfuse-oci.py"
: "${ELFUSE_OCI_STORE:?set ELFUSE_OCI_STORE to the store directory to use}"
export ELFUSE_OCI_STORE

# The library images through mirror.gcr.io, so the lane does not depend on
# Docker Hub's anonymous pull limit.
MIRROR=mirror.gcr.io/library

# Pinned by digest: the store is kept between runs, and a run reuses the digest
# its reference first resolved to.
PYTHON=$MIRROR/python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
NODE=$MIRROR/node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402
REDIS=$MIRROR/redis:7-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499
GOLANG=$MIRROR/golang:1.23-alpine@sha256:383395b794dffa5b53012a212365d40c8e37109a626ca30d6151c8348d380b5f
TEMURIN=$MIRROR/eclipse-temurin:21@sha256:3e3c176ffed168beb42c607be9bc1639b466cf00261a0fb04425562c9d0c5c2b
GCC=$MIRROR/gcc:14@sha256:6f37e44a9b41181de5dd97366ec732652f5d895a72b5549c64694efed50a97e8

key="${1:?usage: oci-runtime.sh <key>}"
WL="$ROOT/scripts/ci/workloads"

guest=""
srv_outfile=""
on_exit()
{
    rc=$?
    # Reap the guest before a persistent runner reuses its port.
    if [ -n "$guest" ] && kill -0 "$guest" 2> /dev/null; then
        kill "$guest" 2> /dev/null || true
        wait "$guest" 2> /dev/null || true
    fi
    if [ "$rc" -ne 0 ] && [ -s "$srv_outfile" ]; then
        echo "--- server guest output ---" >&2
        cat "$srv_outfile" >&2
    fi
    [ -z "$srv_outfile" ] || rm -f "$srv_outfile"
    exit "$rc"
}
trap on_exit EXIT

require_nc()
{
    command -v nc > /dev/null 2>&1 || {
        echo "nc is required" >&2
        exit 2
    }
}

server_printed_or_gone()
{
    server_gone || grep -Eq "$1" "$srv_outfile"
}

server_gone()
{
    ! kill -0 "$guest" 2> /dev/null
}

# Start a server guest in the background and wait for pattern in its output.
# Return 1 if the guest exits first.
start_server()
{
    local pattern="$1"
    shift
    srv_outfile="${srv_outfile:-$(mktemp)}"
    "$@" > "$srv_outfile" 2>&1 &
    guest=$!
    wait_for 60 "server output matching $pattern" server_printed_or_gone "$pattern"
    ! server_gone
}

await_server_exit()
{
    wait_for 10 "$1 exit" server_gone
    wait "$guest" || {
        guest=""
        fail "$1 exited non-zero"
    }
    guest=""
}

run_node()
{
    require_nc
    run_capture node-compute elfuse-oci-node-compute-ok \
        "$BIN" run --entrypoint /usr/local/bin/node "$NODE" \
        -e "$(cat "$WL/node-compute.js")"

    start_server '^PORT=' \
        "$BIN" run --entrypoint /usr/local/bin/node "$NODE" \
        -e "$(cat "$WL/node-server.js")" || fail "node server exited before readiness"
    local port
    port="$(awk -F= '/^PORT=/{print $2; exit}' "$srv_outfile")"
    # Flushed output can precede listen readiness.
    wait_for 30 "node server on 127.0.0.1:$port" nc -z 127.0.0.1 "$port"

    local i=0 reqs=100 body
    local fetch=(curl -fsS --connect-timeout 5 --max-time 10)
    while [ "$i" -lt "$reqs" ]; do
        body="$("${fetch[@]}" "http://127.0.0.1:$port/")" \
            || fail "node server request $i failed"
        [ "$body" = elfuse-node-server-ok ] \
            || fail "node server request $i returned '$body'"
        i=$((i + 1))
    done
    printf 'node server answered %d requests\n' "$reqs"

    # The guest can reset /quit while exiting successfully.
    "${fetch[@]}" -o /dev/null "http://127.0.0.1:$port/quit" || true
    await_server_exit "node server after /quit"
}

run_redis()
{
    require_nc

    # Warm the image, so the readiness wait covers only the server's startup.
    # pull would resolve the digest against the registry even when it is stored.
    "$BIN" run --entrypoint /bin/true "$REDIS"

    # Redis treats port 0 as disabled, and another process can bind the chosen
    # port first; only that failure retries on another port.
    local port try=0
    while :; do
        port=$((20000 + RANDOM % 20000))
        # Make BGSAVE the only background save.
        start_server 'Ready to accept connections' \
            "$BIN" run --entrypoint /usr/local/bin/redis-server "$REDIS" \
            --bind 127.0.0.1 --port "$port" --save '' --dir /data && break
        try=$((try + 1))
        if [ "$try" -ge 10 ] || ! grep -q 'bind: Address in use' "$srv_outfile"; then
            fail "redis server exited before readiness"
        fi
    done
    wait_for 30 "redis server on 127.0.0.1:$port" nc -z 127.0.0.1 "$port"

    run_capture redis-driver elfuse-oci-redis-workload-ok \
        "$BIN" run --entrypoint /bin/sh "$REDIS" \
        -c "$(cat "$WL/redis-driver.sh")" sh "$port"

    await_server_exit "redis server after SHUTDOWN"
}

case "$key" in
    python)
        run_capture python elfuse-oci-python-workload-ok \
            "$BIN" run --entrypoint /usr/local/bin/python3 "$PYTHON" \
            -c "$(cat "$WL/python-workload.py")"

        # A socket path too deep for the host's sun_path is shortened there and
        # must read back as the guest bound it.
        run_capture 'unix socket' elfuse-unix-sock-ok \
            "$BIN" run --entrypoint /usr/local/bin/python3 "$PYTHON" \
            -c "$(cat "$WL/unix-socket.py")"
        ;;
    node) run_node ;;
    redis) run_redis ;;
    go)
        run_capture go elfuse-oci-go-workload-ok \
            "$BIN" run "$GOLANG" /bin/sh -c "$(cat "$WL/go-workload.sh")"
        ;;
    jvm)
        run_capture jvm elfuse-oci-jvm-workload-ok \
            "$BIN" run "$TEMURIN" /bin/sh -c "$(cat "$WL/jvm-workload.sh")"
        ;;
    c)
        run_capture c elfuse-oci-c-workload-ok \
            "$BIN" run "$GCC" /bin/sh -c "$(cat "$WL/c-workload.sh")"
        ;;
    *) fail "unknown runtime key: $key" ;;
esac

echo "runtime $key OK"
