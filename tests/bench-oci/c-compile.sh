#!/bin/sh
# C-compile real-workload benchmark: the c-compile row of the syscall-frequency
# ranking of elfuse (a 30-file C project built with make -j1, then the program
# run). The sources are generated here so the workload needs no download. Runs
# with /bin/sh inside gcc:14 under elfuse; see tests/bench-suite.sh.
#
# SPDX-License-Identifier: Apache-2.0

set -eu
work="$(mktemp -d /tmp/bench-cc.XXXXXX)"
cd "$work"

objs=""
i=1
while [ "$i" -le 30 ]; do
    cat > "unit$i.c" << EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long unit$i(unsigned long seed)
{
    char buf[64];
    unsigned long acc = seed;
    for (int k = 0; k < 1000; k++) {
        snprintf(buf, sizeof(buf), "%lu-%d", acc, k);
        acc = acc * 31 + strlen(buf) + $i;
    }
    return acc;
}
EOF
    objs="$objs unit$i.o"
    i=$((i + 1))
done

{
    echo '#include <stdio.h>'
    i=1
    while [ "$i" -le 30 ]; do
        echo "unsigned long unit$i(unsigned long);"
        i=$((i + 1))
    done
    echo 'int main(void) { unsigned long s = 1;'
    i=1
    while [ "$i" -le 30 ]; do
        echo "s = unit$i(s);"
        i=$((i + 1))
    done
    # printf, not echo: dash's echo would expand the \n in the literal.
    printf '%s\n' 'printf("%lu\n", s); return 0; }'
} > main.c

printf 'CFLAGS = -O1 -Wall\nprog: main.o%s\n\t$(CC) -o $@ $^\n' "$objs" > Makefile
make -j1 -s
./prog > /dev/null
cd /
rm -rf "$work"
