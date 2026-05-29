#!/usr/bin/env bash
# test-go.sh - Go static aarch64 binary vDSO symbol-versioning regression
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# A Go runtime built for linux/arm64 parses the kernel vDSO at startup and walks
# its GNU version-definition table. A vDSO missing .gnu.version_d (DT_VERDEF)
# made runtime.vdsoFindVersion dereference a NULL pointer and SIGSEGV (data
# abort at FAR=0x2) before main(). This generates a tiny Go program, builds it
# for linux/arm64, and runs it under elfuse to guard that path.
#
# Exits 77 (skip) when the Go cross-toolchain is unavailable.

set -euo pipefail

ELFUSE_INPUT="${1:-build/elfuse}"
case "$ELFUSE_INPUT" in
    /*) ELFUSE="$ELFUSE_INPUT" ;;
    *) ELFUSE="$(pwd)/$ELFUSE_INPUT" ;;
esac

if ! command -v go > /dev/null 2>&1; then
    printf 'go toolchain not found; skipping Go vDSO regression\n' >&2
    exit 77
fi
if [ ! -x "$ELFUSE" ]; then
    printf 'elfuse binary not found: %s\n' "$ELFUSE" >&2
    exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# Reaching the print proves the runtime cleared vDSO startup; time.Now() also
# exercises the resolved clock_gettime trampoline. Kept inline rather than as a
# tracked .go file so the C-only tests/ tree stays a non-Go package.
cat > "$WORKDIR/hello.go" <<'EOF'
package main

import (
	"fmt"
	"time"
)

func main() {
	if time.Now().UnixNano() <= 0 {
		panic("vDSO clock returned a non-positive time")
	}
	fmt.Println("hello from go vdso")
}
EOF

if ! GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$WORKDIR/hello-go" \
    "$WORKDIR/hello.go" > "$WORKDIR/build.log" 2>&1; then
    cat "$WORKDIR/build.log" >&2
    printf 'go build for linux/arm64 failed; skipping Go vDSO regression\n' >&2
    exit 77
fi

set +e
out="$("$ELFUSE" "$WORKDIR/hello-go" 2>&1)"
rc=$?
set -e

if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q 'hello from go vdso'; then
    printf 'PASS test-go (Go runtime cleared vDSO startup)\n'
    exit 0
fi

printf 'FAIL test-go: rc=%d\n' "$rc" >&2
printf '%s\n' "$out" >&2
exit 1
