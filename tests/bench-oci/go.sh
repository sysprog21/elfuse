#!/bin/sh
# Go real-workload benchmark: the go row of the syscall-frequency ranking in
# elfuse (`go version`, then gofmt over standard-library trees). Runs with
# /bin/sh inside golang:1.23-alpine under elfuse; see tests/bench-suite.sh.
#
# SPDX-License-Identifier: Apache-2.0

set -eu
root="$(go env GOROOT)"
go version > /dev/null
for tree in net runtime crypto; do
    gofmt -l "$root/src/$tree" > /dev/null
done
gofmt -d "$root/src/fmt" > /dev/null
