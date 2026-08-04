# Building And Testing

This document describes the development toolchain, the main `make` targets, and
how the repository validation flow is structured.

## Build Requirements

Host build requirements:

- Apple Silicon macOS host
- macOS 13 or newer
- Xcode Command Line Tools
- `clang`
- `codesign`
- GNU `make`
- GNU `objcopy` or `llvm-objcopy`
- GNU coreutils
- `bash` 3.2+ (the version Apple ships as `/bin/bash`) is sufficient for
  the test harness; no Homebrew `bash` is required. See
  `tests/lib/bash-compat.sh` for the cross-version shims (a portable
  microsecond clock and the parallel-array lookup pattern that replaces
  associative arrays). When editing a shell script under `tests/` or
  `scripts/`, the conventions in that file's header are the source of
  truth: no `EPOCHREALTIME`, no `declare -A`, no `mapfile`, no
  `${var^^}` / `${var,,}` case-conversion, and guard any potentially
  empty array expansion with `${arr[@]+"${arr[@]}"}` so `set -u` does
  not trip on it.
- Hypervisor entitlement: `com.apple.security.hypervisor`

Guest test builds additionally require:

- An AArch64 Linux cross-compiler for C test programs
- An AArch64 bare-metal toolchain for the assembly smoke test

The toolchain defaults are defined in `mk/toolchain.mk`. 
These variables are intended to be overridden when needed:

- `CROSS_COMPILE`
- `BAREMETAL_CROSS`
- `SIGN_IDENTITY`

### Installing the toolchains with Homebrew

The following block installs everything needed to run both `make check` and
the full `make test-matrix` (including the `qemu-aarch64` reference run). Run it
once on an Apple Silicon macOS host:

```sh
# GNU coreutils (gtimeout) — required by the test harness timeout wrapper
brew install coreutils

# GNU objcopy
brew install binutils

# Bare-metal aarch64-none-elf toolchain used by `make check`
brew install --cask gcc-aarch64-embedded

# AArch64 Linux cross-compiler for guest test binaries (make test-matrix)
brew tap messense/macos-cross-toolchains
brew trust --formula messense/macos-cross-toolchains/aarch64-unknown-linux-gnu
brew install aarch64-unknown-linux-gnu

# QEMU — boots the Alpine minirootfs for the qemu-aarch64 reference run
brew install qemu
```

Depending on your setup, you might need to add the following to your PATH
```
export PATH="/opt/homebrew/opt/aarch64-elf-gcc/bin:$PATH"
```

## Main Targets

The most useful development targets are:

```sh
make elfuse
make check
make test-rosetta-all
make test-gdbstub
make test-matrix
make lint
make clean
```

What they do:

- `make elfuse`: build and sign `build/elfuse`
- `make check`: fast elfuse-internal gate. Runs, in order:
  - `scripts/check-syscall-coverage.py` so any new `dispatch.tbl`
    entry without a direct or aliased test reference fails the build
  - the unit suite from `tests/manifest.txt` -- deliberately narrow: only
    tests that assert elfuse-internal implementation details with no real
    Linux counterpart (the EL1 shim fast-path suite, `test-mremap-infra`,
    `test-oom-proc`), plus whatever `mk/tests.mk`'s `SANITIZER_SECTIONS`
    needs for the `check-{asan,ubsan,tsan}` lanes. Everything that is
    meaningful to cross-check against a real Linux kernel lives exclusively
    in `tests/test-matrix.sh`'s `run_unit_tests` instead (see Test Matrix
    below) -- `make check` alone is *not* a substitute for it
  - the TLBI RVAE1IS encoder unit test
  - the proctitle argv-tail and low-stack regressions
  - the BusyBox applet smoke suite (auto-resolved from
    `externals/test-fixtures/aarch64-musl/staticbin/bin/busybox` or
    downloaded into `build/busybox` on first run)
  - the sysroot procfs exec, FUSE-on-Alpine, and `timeout=0` regressions
  - the Rosetta CLI gating regressions
  - the hot-syscall guardrail (`tests/test-bench-guardrail.sh`)
    asserting `getpid`, libc `clock_gettime`, and 1-byte
    `/dev/urandom` reads stay under their ns/op ceilings
- `make test-rosetta-all`: Rosetta-specific x86_64 acceptance scripts
  (`test-rosetta-cli`, `test-rosetta-failure-modes`,
  `test-rosetta-statics`, `test-rosetta-alpine`,
  `test-rosetta-audit`, `test-rosetta-jit`, `test-rosetta-glibc`)
- `make test-busybox`: just the BusyBox suite, useful when iterating on a
  single applet failure without rerunning the unit suite
- `make test-fuse-alpine`: validate guest `/dev/fuse` + `mount("fuse")`
  against the Alpine musl sysroot fixture
- `make test-gdbstub`: debugger integration checks against the built-in GDB stub
- `make test-matrix`: cross-check `elfuse` (aarch64), QEMU (aarch64),
  and `elfuse` (x86_64-via-Rosetta) on overlapping corpora
- `make bench`: two-tier performance benchmark suite (see Performance
  Benchmarks below); `make bench-ci` is the strict CI variant
- `make lint`: static analysis through `clang-tidy`

## Quick Iteration

For normal code changes touching syscall or runtime logic:

```sh
make elfuse
make check
make test-matrix-elfuse-aarch64
```

`make check` alone only covers elfuse-internal plumbing and the sanitizer
subset now; `test-matrix-elfuse-aarch64` is what actually exercises the full
unit-test surface against `build/elfuse`.

```sh
make test-matrix-qemu-aarch64
```

or run all matrix modes back-to-back with `make test-matrix`.

## Performance Benchmarks

`make bench` runs `tests/bench-suite.sh`, the two-tier suite, and
writes `build/bench-results.json`:

- Tier 1 -- lmbench (issue #195): `lat_syscall`
  (null/read/write/stat/open) for syscall entry/forwarding cost,
  `lat_proc` (fork, fork+execve) for process creation and the ELF-load
  path, and `lat_fs -s 1024` (1 KiB create/delete only).

- Tier 2 -- application workloads over the fixed corpus in
  `tests/bench-corpus/` using Alpine fixture tools: `python3 -c pass`,
  `git status`, `rg`, `zstd`, and `make`. `rg` searches 512 deterministic
  copies of the source tree (~87 MiB, tens of thousands of files) and
  `zstd` compresses a matching ~87 MiB input -- fixed sizes chosen so
  command startup and scheduler jitter don't dominate what would
  otherwise be millisecond-scale workloads

Each metric runs warmup + timed iterations and reports the median plus
raw samples. `scripts/bench-compare.py` diffs the results against
`tests/bench-baseline.json` and exits non-zero on a metric regressing
past the threshold (default +20%, `BENCH_REGRESSION_THRESHOLD`) or
missing from the current run; `BENCH_REPORT_ONLY=1` downgrades that to
a log-only signal, which is how the CI `Benchmark` leg runs.

CI measures only the `elfuse-aarch64` column. `qemu-aarch64` (a real
Linux kernel on the same silicon) and the optional `orbstack` column
are static references, captured manually per the refresh procedure
below.

`BENCH_ENV=qemu-aarch64 make bench` produces the `qemu-aarch64`
reference column; `BENCH_ENV=orbstack` runs the workloads inside the
default OrbStack machine (Tier-2 tools must be installed there);
`BENCH_ENV=native` also works on an aarch64 Linux host.

Do not edit `tests/bench-corpus/` -- the corpus is part of the benchmark
definition, and any change to it invalidates the baseline.

### Manual / Ad-hoc Runs

Prefer the Makefile targets (`bench` / `bench-ci`, `BENCH_ENV` picks the
column) for a full run -- they build the prerequisites and wire up
`ELFUSE`/`BENCH_BIN_DIR`. The commands below drive the same pieces
directly, useful for iterating on one case or comparing an existing
results file without rerunning everything.

**Full suite with custom env/output:**

```sh
BENCH_ENV=elfuse-aarch64 BENCH_ITERATIONS=20 BENCH_WARMUP=3 \
    bash tests/bench-suite.sh -o build/bench-results.json
```

`BENCH_ENV` selects the column (`elfuse-aarch64` default,
`qemu-aarch64`, `orbstack`, `native`); the CI variant just adds
`BENCH_STRICT=1` (fetch fixtures on demand, fail hard instead of
skipping Tier 2 when they're missing).

**One Tier-1 benchmark without the suite harness:**

```sh
tests/fetch-fixtures.sh                # builds the lmbench fixtures once
env ENOUGH=100000 ./build/elfuse \
    externals/test-fixtures/aarch64-musl/staticbin/bin/busybox \
    sh -c '"$0" "$@"; exit $?' \
    externals/test-fixtures/aarch64-musl/lmbench/lat_syscall -N 5 null
```

**One Tier-2 workload's wall-clock cost:**

```sh
./build/elfuse --sysroot externals/test-fixtures/rootfs \
    ./build/bench-timeit /bin/busybox true
```

**Compare an existing results file against baseline without rerunning:**

```sh
python3 scripts/bench-compare.py --results build/bench-results.json \
    --baseline tests/bench-baseline.json --threshold 0.20 \
    --report-json build/bench-pr-report.json
```

Add `--report-only` (or `BENCH_REPORT_ONLY=1`) to print regressions
without a non-zero exit. Any file matching the schema in
`tests/bench-suite.sh`'s header works, including one captured with
`BENCH_ENV=qemu-aarch64`/`orbstack`/`native`.

**Promote a captured results file into the baseline:**

```sh
python3 scripts/bench-promote.py --results build/bench-results.json \
    --baseline tests/bench-baseline.json
```

**Environment variables** (all optional; defaults shown):

| Variable | Default | Meaning |
| --- | --- | --- |
| `BENCH_ENV` | `elfuse-aarch64` | column: `elfuse-aarch64` \| `qemu-aarch64` \| `orbstack` \| `native` |
| `BENCH_ITERATIONS` | `10` | timed Tier-2 samples per metric |
| `BENCH_WARMUP` | `2` | discarded leading Tier-2 samples per metric |
| `BENCH_LMBENCH_REPS` | `1` | lmbench `-N` repetitions per Tier-1 outer sample; outer samples provide the median |
| `BENCH_LMBENCH_RETRIES` | `1` | extra attempts for a failed/hung Tier-1 benchmark before its `ERR` row |
| `BENCH_LMBENCH_TIMEOUT` | `60` | per-lmbench-invocation timeout in seconds |
| `BENCH_LMBENCH_ENOUGH` | `100000` | lmbench `ENOUGH` (us per timing interval); empty restores lmbench auto-calibration |
| `LMBENCH_DIR` | fixtures `aarch64-musl/lmbench` | directory holding the lmbench fixture binaries |
| `BENCH_STRICT` | `0` | `1` = missing fixtures are fatal and fetched on demand (what `bench-ci` sets) |
| `ELFUSE` | `build/elfuse` | elfuse binary driving the elfuse-aarch64 column |
| `BENCH_BIN_DIR` | `build/` | directory holding `bench-timeit` |
| `TEST_TIMEOUT` | `120` | per-invocation timeout in seconds |
| `BENCH_QEMU_NULL_CEILING` | `180` | ns/op; the qemu boot-calibration probe reboots the VM above this (efficiency-core placement) |
| `BENCH_QEMU_BOOT_RETRIES` | `2` | qemu boot-calibration retry attempts before proceeding with a warning |
| `BENCH_REGRESSION_THRESHOLD` | `0.20` | fractional regression that fails `bench-compare.py` |
| `BENCH_REPORT_ONLY` | unset | `1` = `bench-compare.py` reports regressions but exits 0 |

## Test Matrix

The matrix driver lives in `tests/test-matrix.sh` and covers three
execution modes:

- `elfuse-aarch64`: every binary executed via `build/elfuse` on macOS
- `qemu-aarch64`: the same binaries run natively inside an Alpine
  `aarch64-linux-musl` minirootfs booted by `qemu-system-aarch64`
- `elfuse-x86_64`: Rosetta-for-Linux acceptance scripts against the
  staged Alpine x86_64 fixture tree

The goal is to compare guest-observable behavior against a
ground-truth Linux AArch64 environment, not performance, so any
divergence in syscall translation, procfs emulation, or process
semantics is caught early.

`run_unit_tests` runs almost the entire aarch64 unit-test surface, in
both `elfuse-aarch64` and `qemu-aarch64` modes -- excluding only the
elfuse-internal tests already covered by `make check` (see
`tests/manifest.txt`) and the known divergences listed in `QEMU_SKIP`.
The x86_64 mode aggregates the Rosetta-specific acceptance scripts
instead.

Run a single mode with `bash tests/test-matrix.sh elfuse-aarch64`,
`qemu-aarch64`, or `elfuse-x86_64`; `all` runs all three back-to-back.

## Rosetta Limitations

`elfuse-x86_64` inherits two Rosetta-internal limitations not treated
as elfuse regressions:

- `SA_RESETHAND` is not reset reliably (Rosetta shadows guest signal
  handler state internally).
- `clone(..., CLONE_SETTLS, tls=0, ...)` can hang.

The x86_64 matrix branch is a Rosetta acceptance gate, not a claim of
full native Linux thread/signal parity.

## x86_64 Acceptance Inventory and Per-Host Baselines

The `elfuse-x86_64` matrix mode aggregates seven sub-suites. Each
emits a deterministic per-binary pass list; the matrix runner sums
them into one `Results:` line and compares against a per-host
baseline:

- `tests/test-rosetta-cli.sh` (4) -- command-line gating of the
  translator path (opt-out flag, env override, `--gdb` rejection,
  install-hint surface).
- `tests/test-rosetta-failure-modes.sh` (3) -- command-line rejection
  paths, self-contained against a synthesized minimal x86_64 ELF.
- `tests/test-rosetta-statics.sh` (20) -- statically-linked Alpine
  busybox applets, exercising the VZ ioctl gate, `/proc/self/exe`
  redirect, high-VA mmap, and the kbuf alias.
- `tests/test-rosetta-alpine.sh` (33) -- broader file I/O, text
  processing, and host-shell pipelines through Rosetta.
- `tests/test-rosetta-audit.sh` (2) -- bookkeeping probe asserting the
  documented Rosetta shadowing failures (above) remain the only
  divergences.
- `tests/test-rosetta-jit.sh` (2) -- guest-side JIT under translation
  (LuaJIT trace emission + coroutine allocation).
- `tests/test-rosetta-glibc.sh` (7) -- dynamically-linked glibc x86_64
  binary acceptance through `--sysroot` against the staged minimal
  glibc rootfs: load-time `PT_INTERP`/`ld.so` resolution, `dlopen`,
  and TLS (initial-exec, general-dynamic, per-thread).

Total: 71 expected passes, 0 expected failures.

### Per-Host Baseline Capture

The matrix runner keys its `elfuse-x86_64` baseline by detected host
SoC class, since `sys_mmap_fixed_high_va` takes different paths under
different IPA widths:

- `apple-m1-m2`: 36-bit native IPA (overflow-segment path). Captured
  on Apple M1 hardware; lands at 71/0/0.
- `apple-m3-plus`: 40-bit native IPA (bisected-slab path). Currently
  held equal to `apple-m1-m2` pending real M3+ hardware capture.
- `apple-unknown`: fallback for unrecognized SoC strings; inherits the
  M1/M2 numbers with a one-line warning.

Class detection reads `sysctl -n machdep.cpu.brand_string`. Override
with `MATRIX_HOST_CLASS_OVERRIDE=apple-m3-plus` (or `apple-m1-m2`,
`apple-unknown`) to exercise a different row without changing host.

When the sub-suites change, update the per-suite counts in
`EXPECTED_BASELINES` (`tests/test-matrix.sh`) and the inventory above
in the same commit so the baseline stays in sync.

## Test Inventory

The repository contains several layers of validation:

- unit-style guest tests compiled from `tests/*.c`
- shell integration suites such as BusyBox, coreutils, and dynamic-loader tests
- debugger integration tests for the GDB stub
- native macOS HVF checks such as multi-vCPU and RWX validation

The quick suite is driven by `tests/driver.sh`, which supports:

- `-f PATTERN` to filter tests
- `-l` to list them
- `-T` for TAP output

Example:

```sh
bash tests/driver.sh -f test-proc
```

## Validation Strategy By Change Type

Suggested minimum validation:

| Change area | Recommended validation |
|-------------|------------------------|
| CLI, logging, docs-only build rules | `make elfuse` |
| General syscall or runtime logic | `make elfuse && make check && make test-matrix-elfuse-aarch64` |
| `/proc`, `/dev`, path, or BusyBox-sensitive behavior | `make elfuse && make check && make test-matrix-elfuse-aarch64` |
| Rosetta hosting, x86_64 dispatch, VZ ioctls, AOT cache | `make elfuse && make test-rosetta-all` |
| Broad behavioral changes | `make elfuse && make check && make test-matrix` |
| Debugger or ptrace flow | `make elfuse && make test-gdbstub` |
