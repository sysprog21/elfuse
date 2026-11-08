#!/bin/sh
# JVM real-workload benchmark driver: compiles tests/bench-oci/jvm/*.java with
# javac and runs the result. Runs with /bin/sh inside eclipse-temurin:21 under
# elfuse; the first argument is the directory holding the sources. See
# tests/bench-suite.sh.
#
# SPDX-License-Identifier: Apache-2.0

set -eu
src="$1"
work="$(mktemp -d /tmp/bench-jvm.XXXXXX)"
cp "$src"/*.java "$work/"
javac -d "$work/classes" "$work"/*.java
java -cp "$work/classes" Bench > /dev/null
rm -rf "$work"
