# shellcheck shell=sh
# Exercise Go filesystem traversal, goroutine scheduling, and async preemption.
set -e

export GOCACHE=/tmp/elfuse-go-cache

# elfuse reports one CPU, so GOMAXPROCS=2 keeps the workload concurrent.
export GOMAXPROCS=2

go version

d=/tmp/elfuse-go-work
mkdir -p "$d/src"
cd "$d/src"

# Generate fixed inputs independent of image contents.
n=64
i=1
while [ "$i" -le "$n" ]; do
    printf 'package p\n\nfunc F%s()  {\n\tx :=1\n\t_ = x\n}\n' "$i" > "f$i.go"
    i=$((i + 1))
done

gofmt -l . > "$d/list"
listed=$(wc -l < "$d/list" | tr -d ' ')
if [ "$listed" != "$n" ]; then
    echo "gofmt -l named $listed files, expected $n" >&2
    cat "$d/list" >&2
    exit 1
fi

gofmt -w .

printf 'package p\n\nfunc F7() {\n\tx := 1\n\t_ = x\n}\n' > "$d/f7.expected"
if ! cmp -s f7.go "$d/f7.expected"; then
    echo "f7.go after gofmt -w:" >&2
    cat f7.go >&2
    exit 1
fi

gofmt -l . > "$d/list"
remaining=$(wc -l < "$d/list" | tr -d ' ')
if [ "$remaining" != "0" ]; then
    echo "gofmt -l still names $remaining files after -w" >&2
    cat "$d/list" >&2
    exit 1
fi

root=$(go env GOROOT)
if [ ! -x "$root/bin/go" ]; then
    echo "go env GOROOT gave $root, which holds no go binary" >&2
    exit 1
fi

# On one P, main runs again only if a signal preempts the spinning goroutine.
mkdir -p "$d/spin"
cd "$d/spin"
cat > main.go << 'EOF'
package main

import "time"

func main() {
	go func() {
		for {
		}
	}()
	time.Sleep(100 * time.Millisecond)
}
EOF
go build -o spin main.go
if ! GOMAXPROCS=1 timeout 60 ./spin; then
    echo "a spinning goroutine was not preempted within 60s" >&2
    exit 1
fi

echo "elfuse-oci-go-workload-ok files=$n formatted=$n"
