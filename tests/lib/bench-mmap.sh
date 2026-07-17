#!/usr/bin/env bash
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

human()
{
    awk -v n="$1" 'BEGIN {
        if (n >= 1073741824) printf "%g GiB", n / 1073741824
        else if (n >= 1048576) printf "%g MiB", n / 1048576
        else printf "%g KiB", n / 1024
    }'
}

# field <output> <key> Prints the value of the first "<key>=<value>" token in
# <output>.
field()
{
    local value
    if ! value="$(awk -v key="$2" '{
        for (i = 1; i <= NF; i++) {
            if (index($i, key "=") == 1) {
                sub("^" key "=", "", $i)
                print $i
                found = 1
                exit
            }
        }
    }
    END {
        if (!found)
            exit 1
    }' <<< "$1")"; then
        printf 'benchmark output missing %s field:\n%s\n' "$2" "$1" >&2
        return 1
    fi
    printf '%s\n' "$value"
}

numeric_median()
{
    printf '%s\n' "$@" | LC_ALL=C sort -n | awk '{ values[NR] = $1 }
    END {
        if (NR % 2)
            print values[(NR + 1) / 2]
        else
            print (values[NR / 2] + values[NR / 2 + 1]) / 2
    }'
}
