# shellcheck shell=sh
# Compile a C project under POSIX sh with a tab-free generated Makefile.
set -e

d=/tmp/elfuse-c-work
mkdir -p "$d"
cd "$d"

cat > mathx.h << 'EOF'
#ifndef MATHX_H
#define MATHX_H
int tri(int n);
#endif
EOF
cat > mathx.c << 'EOF'
#include "mathx.h"
int tri(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++) s += i;
    return s;
}
EOF
cat > main.c << 'EOF'
#include <stdio.h>
#include "mathx.h"
int main(void) {
    printf("%d\n", tri(100));
    return 0;
}
EOF
cat > Makefile << 'EOF'
.RECIPEPREFIX = >
app: main.o mathx.o
> $(CC) -O1 -o app main.o mathx.o
%.o: %.c mathx.h
> $(CC) -O1 -c -o $@ $<
EOF

make -j1
r=$(./app)
if [ "$r" != "5050" ]; then
    echo "make project produced: $r" >&2
    exit 1
fi

awk 'BEGIN {
    for (i = 0; i < 1000; i++) print "int f" i "(void){return " i ";}";
    printf "typedef int(*fn)(void);\nstatic fn t[]={";
    for (i = 0; i < 1000; i++) printf "f%d,", i;
    print "};";
    print "int main(void){long s=0;for(int i=0;i<1000;i++)s+=t[i]();return s==499500?0:1;}";
}' > big.c
gcc -O1 -o big big.c
./big

echo elfuse-oci-c-workload-ok
