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
# GNU coreutils (gtimeout): required by the test harness timeout wrapper
brew install coreutils

# GNU objcopy
brew install binutils

# Bare-metal aarch64-none-elf toolchain used by `make check`
brew install --cask gcc-aarch64-embedded

# AArch64 Linux cross-compiler for guest test binaries (make test-matrix)
brew tap messense/macos-cross-toolchains
brew trust --formula messense/macos-cross-toolchains/aarch64-unknown-linux-gnu
brew install aarch64-unknown-linux-gnu

# QEMU: boots the Alpine minirootfs for the qemu-aarch64 reference run
brew install qemu
```

Depending on the setup, the bare-metal toolchain may also need adding to
`PATH`:

```sh
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
  - `scripts/check-lock-order.py` so a new file-scope `pthread_mutex_t`
    or `pthread_rwlock_t` that the lock-ordering block at the top of
    `src/syscall/internal.h` does not name fails the build. Membership
    only: whether the lock belongs in the ordered list or the leaf list
    stays a judgement for review
  - the unit suite from `tests/manifest.txt` -- deliberately narrow: the
    elfuse-internal implementation tests with no real Linux counterpart (the
    EL1 shim fast-path suite, `test-mremap-infra`, `test-mremap-fork-tracking`,
    and `test-oom-proc`), plus `test-mremap-tail-emfile`, whose host-reserve
    regression also runs in the elfuse matrix lane, and whatever
    `mk/tests.mk`'s `SANITIZER_SECTIONS`
    needs for the `check-{asan,ubsan,tsan}` lanes. Everything that is
    meaningful to cross-check against a real Linux kernel lives exclusively
    in `tests/test-matrix.sh`'s `run_unit_tests` instead (see Test Matrix
    below) -- `make check` alone is *not* a substitute for it
  - the TLBI RVAE1IS encoder unit test
  - the proctitle argv-tail and low-stack regressions
  - the BusyBox applet smoke suite (auto-resolved from
    `externals/test-fixtures/aarch64-musl/staticbin/bin/busybox` or
    downloaded into `build/busybox` on first run)
  - the filename codec and case-exact path resolution unit tests
  - the sysroot lanes, each a recipe in `mk/tests.mk` that provisions
    its own sysroot and asserts the on-disk shape host-side after the
    guest exits: the filename family (one representation per name,
    relative and dirfd-relative names, non-ASCII, full length,
    host-staged escape shapes, concurrent colliding creates), the
    edge shapes (sysroot at `/`, no sysroot, the guest-visible cwd),
    byte-exact lookup, host fallback, symlink escapes and targets,
    case collisions, the decode boundary (inotify names, exec
    identity, `PT_INTERP`, pathname `AF_UNIX` sockets), the host
    path ceiling (`ENAMETOOLONG` where macOS's 1024-byte `PATH_MAX`
    undercuts the guest's 4096, a macOS-only boundary, which is why
    the lane is absent from the qemu matrix), and the frozen-spelling
    corpus (on-disk escapes staged byte-for-byte from
    `tests/casefold-vectors.h` and read back through a live sysroot)
  - the byte-exact oracle lane (`check-name-caseexact`): the name
    suite re-run against a case-sensitive APFS sparsebundle. The
    volume itself enforces the byte-exact matching the tests assert,
    so a failure there means a test's expectation (not the volume)
    is wrong, whatever the folding lane says of it. The i18n lane
    runs in its `csapfs` mode, pinning the two divergences that
    configuration accepts (see `docs/filenames.md`)
  - the sysroot procfs exec, FUSE-on-Alpine, and `timeout=0` regressions
  - the Rosetta CLI gating regressions
  - the hot-syscall guardrail (`tests/test-bench-guardrail.sh`)
    asserting `getpid`, libc `clock_gettime`, and 1-byte
    `/dev/urandom` reads stay under their ns/op ceilings
- `make test-rosetta-all`: Rosetta-specific x86_64 acceptance scripts
  (`test-rosetta-cli`, `test-rosetta-failure-modes`,
  `test-rosetta-statics`, `test-rosetta-alpine`,
  `test-rosetta-audit`, `test-rosetta-jit`, `test-rosetta-glibc`)
- `make test-sysroot-name-soak`: minutes of threaded and forked churn over
  one case-colliding name set (`SECS=N` overrides the default 120). Excluded
  from `check` for its runtime; a pass is only the absence of a reproducer,
  and the invariants are stated in `tests/test-sysroot-name-soak.c`
- `make test-busybox`: just the BusyBox suite, useful when iterating on a
  single applet failure without rerunning the unit suite
- `make test-fuse-alpine`: validate guest `/dev/fuse` + `mount("fuse")`
  against the Alpine musl sysroot fixture
- `make test-gdbstub`: debugger integration checks against the built-in GDB stub
- `make test-sharun`: run sharun and its probe under elfuse in six arms of
  increasing host requirements. The prebuilt launcher (`--version`) is a static
  aarch64 ELF and runs anywhere elfuse does; the x86_64 build of the same
  release goes through the Rosetta path as a static-pie musl Rust binary, a
  shape no other lane covers, and skips without the translator. The cross-built
  probe covers the loader path (`DT_NEEDED`, `dlopen`, `$ORIGIN` rpath, libm,
  pthreads, fork) that no other aarch64 lane reaches, and skips without the
  cross-glibc sysroot. Three further arms drive a bundle: the probe under the
  real launcher, `--gen-lib-path` walking the tree and writing back to it from
  inside the guest, and the negative path where the `dlopen` target is removed
  and the loader's errno must surface rather than hang or crash. Nothing shells
  out to `lib4bin`, so there is no Linux dependency: `tests/build-sharun-bundle.sh`
  writes the bundle layout directly from the launcher, the probe, and a prebuilt
  Debian glibc fetched by `tests/fetch-glibc.sh`. Point `SHARUN_FIXTURE_DIR` at
  an unpacked bundle to test one built elsewhere instead. The lane skips
  entirely with status 77 in two cases: it cannot reach the launcher for the
  first arm, or that arm passed but every dynamic-loader arm skipped (no
  cross-glibc sysroot and no `SHARUN_FIXTURE_DIR`). The second
  keeps a run that covered only the static launcher from reporting the same
  green as one that exercised the loader. Launcher
  binaries and the glibc package are pinned and digest-checked by
  `tests/sharun-fixture.lock` and cached under `$FIXTURES_DIR`, so they download
  once and survive `make clean`. Every download happens inside the lane rather
  than as a make prerequisite, so an unreachable network skips the affected arms
  instead of failing `make check`. Editing a probe source under
  `tests/fixtures/sharun/` is picked up on the next run: make rebuilds
  `$(BUILD_DIR)/probe` and its two DSOs from those sources, and the bundle is
  assembled from the rebuilt binaries. It also runs as a lane of `make check`.
- `make test-matrix`: cross-check `elfuse` (aarch64), QEMU (aarch64),
  and `elfuse` (x86_64-via-Rosetta) on overlapping corpora
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
unit-test surface against `build/elfuse` (no qemu boot needed, so it is about
as fast to iterate with as `make check` was before the split). For changes
that touch procfs, path handling, `/dev`, FUSE, networking, dynamic linking,
or guest process semantics, also cross-check against the qemu reference
kernel:

```sh
make test-matrix-qemu-aarch64
```

or run all matrix modes back-to-back with `make test-matrix`.

`make check` already runs the BusyBox applet suite as a second stage, so a
green `make check` covers BusyBox validation. Use `make test-busybox` to
iterate on a single applet failure without rerunning the unit suite.

## Test Matrix

The matrix driver lives in `tests/test-matrix.sh`. It currently covers three
execution modes:

- `elfuse-aarch64`: every binary is executed via `build/elfuse` on macOS
- `qemu-aarch64`: the same binaries run natively inside an Alpine
  `aarch64-linux-musl` minirootfs booted by `qemu-system-aarch64`
- `elfuse-x86_64`: Rosetta-for-Linux acceptance scripts against the staged
  Alpine x86_64 fixture tree

The goal is not to compare performance. The goal is to compare guest-observable
behavior against a ground-truth Linux AArch64 environment so that any divergence
in syscall translation, procfs emulation, or process semantics is caught early.

`run_unit_tests` in `tests/test-matrix.sh` is the full aarch64 unit-test
surface -- every binary that is meaningful to run against a real kernel, which
is almost everything. It deliberately excludes only the handful of tests that
assert elfuse-internal implementation details with no meaningful counterpart
on a real kernel (the EL1 shim fast-path suite, `test-mremap-infra`,
`test-mremap-fork-tracking`, and `test-oom-proc` -- these live solely in
`tests/manifest.txt` / `make check`, see that file's header for the full split
rationale). `test-mremap-tail-emfile` is the exception: it is also listed in
`run_unit_tests` for the `elfuse-aarch64` lane and is `QEMU_SKIP`'d because its
host-reserve assertion has no real-kernel counterpart. There is no separate
"core" vs "extended" test set inside the matrix; a test that has a real,
understood divergence from the qemu reference kernel is listed in
`QEMU_SKIP` with a comment explaining why instead -- see that variable in
`tests/test-matrix.sh` for the current list and rationale. `run_unit_tests`
runs in both `elfuse-aarch64` and `qemu-aarch64` modes, so most tests are
exercised twice per matrix run: once against `build/elfuse`, once against the
real kernel.

`ELFUSE_SKIP` is the same mechanism pointing the other way: tests that run only
against the reference kernel. A test belongs there when it needs something the
elfuse lane cannot provide: most often a writable, byte-exact root, which that
lane has no sysroot to give and which the macOS root is not. A skip is not a
pass, so the `elfuse-aarch64` row of `EXPECTED_BASELINES` does not move when a
test is added to the list.

Both lists match a test by its label, and a label matching nothing fails
silently while still reading as deliberate policy, so
`.ci/check-matrix-lists.sh` rejects a label that names no registered test and a
label present in both lists, which would run under no runner at all.

The filename tests are `ELFUSE_SKIP`'s main occupants. They assert that names
differing only in case, or only in Unicode normalization, stay distinct,
exactly what a case-folding host volume is entitled to get wrong. Running them
against the VM's tmpfs turns those expectations into measurements; their
elfuse-side coverage is the `make check` sysroot lanes, where a real sysroot
exists.

The x86_64 mode is narrower: it aggregates the Rosetta-specific acceptance
scripts and their per-binary summaries into the same matrix runner, including
the Rosetta thread/signal audit smoke, the LuaJIT guest-JIT probe, and the
glibc dynamic-binary acceptance helper.

Run a single mode with `bash tests/test-matrix.sh elfuse-aarch64`,
`bash tests/test-matrix.sh qemu-aarch64`, or
`bash tests/test-matrix.sh elfuse-x86_64`; `all` runs all three back-to-back.

Fixture handling is self-contained:

- On first use, `tests/fetch-fixtures.sh` downloads the required Alpine
  packages and the `linux-virt` kernel into `externals/test-fixtures/` and
  assembles an initramfs. Subsequent runs are zero-config.
- The same fixture tree is reused across the matrix modes.
- When Rosetta mode is requested and the translator is installed,
  `tests/test-matrix.sh` auto-fetches the x86_64 fixture tree
  (`INCLUDE_X86_64=1`) on demand.
- QEMU mode requires `qemu-system-aarch64` on `PATH` (Homebrew `qemu` provides it).
- musl is the only Alpine libc; the glibc-dynamic suite is skipped unless
  `GUEST_GLIBC_*` environment variables point at an external sysroot.

## Rosetta Limitations

`elfuse-x86_64` is expected to inherit two Rosetta-internal limitations that are
not treated as elfuse regressions:

- `SA_RESETHAND` is not reset reliably because Rosetta shadows guest signal
  handler state internally.
- `clone(..., CLONE_SETTLS, tls=0, ...)` can hang.

The x86_64 matrix branch is therefore a Rosetta acceptance gate, not a claim
that translated guests fully match native Linux thread and signal semantics.

## x86_64 Acceptance Inventory and Per-Host Baselines

The `elfuse-x86_64` matrix mode aggregates seven sub-suites. Each one
emits a deterministic per-binary pass list; the matrix runner sums
those into a single `Results:` line and compares against a per-host
baseline. The exact labels each sub-suite emits, and the contract
they verify, are:

- `tests/test-rosetta-cli.sh` (4): `rosetta-disabled-flag`,
  `rosetta-disabled-env`, `rosetta-gdb`, `rosetta-default` --
  command-line gating of the translator path (opt-out flag, env
  override, `--gdb` rejection, install-hint surface).

- `tests/test-rosetta-failure-modes.sh` (3): `no-rosetta-flag`,
  `no-rosetta-env`, `gdb-x86_64` -- command-line rejection paths.
  Self-contained against a synthesized minimal x86_64 ELF; no
  external fixture tree required. The dynamic-linker bring-up and
  mid-process execve scenarios that used to live here are now
  exclusively in the glibc and statics suites against the vendored
  rootfs (see `glibc-hello` / `glibc-hello-via-ldso` and
  `env-execve`).

- `tests/test-rosetta-statics.sh` (20): `echo`, `true`, `false`,
  `printenv`, `expr-zero`, `expr-mul`, `basename`, `dirname`,
  `stat-self`, `factor`, `seq`, `sha256sum`, `md5sum`, `uname-m`, `arch`,
  `busybox-arch-subcommand`, `date-utc`, `id-u`, `nproc`,
  `env-execve` -- statically-linked Alpine busybox applets,
  exercising VZ ioctl gate, `/proc/self/exe` redirect, high-VA mmap,
  and the kbuf alias.

- `tests/test-rosetta-alpine.sh` (33): `cat-fruits-first-line`,
  `wc-l-fruits`, `wc-l-lines`, `wc-c-lines`, `ls-data`, `stat-data`,
  `find-by-name`, `du-sk-data`, `sha256-fruits`,
  `sha256-lines-matches-host`, `sha512-lines`, `md5-fruits`,
  `cksum-fruits`, `sort-first`, `sort-reverse-first`, `pipe-sort-wc`,
  `pipe-tr-uppercase`, `pipe-cat-grep`, `pipe-sed-subst`,
  `pipe-awk-field`, `head-n3`, `tail-n3`, `pipe-sort-uniq`,
  `pipe-cut-field`, `pipe-rev`, `tac-reverse-first-line`, `seq-1-5`,
  `seq-step`, `factor-prime`, `factor-composite`, `diff-identical`,
  `diff-differs`, `pipe-base64-decode` -- broader file I/O, text
  processing, and host-shell pipelines stitched through Rosetta on
  every stage.

- `tests/test-rosetta-audit.sh` (2): `audit-known-limitations`,
  `tls0-known-hang` -- bookkeeping probe that asserts the documented
  Rosetta shadowing failures (above) remain the only divergences;
  fails loudly if a new threading/signal-state edge case starts
  diverging.

- `tests/test-rosetta-jit.sh` (2): `luajit-trace`,
  `luajit-coroutine` -- guest-side JIT under translation
  (LuaJIT trace emission + coroutine allocation), covering the
  small-mprotect RW->RX and per-thread icache observation path that
  rosetta's own JIT does not exercise.

- `tests/test-rosetta-glibc.sh` (7): `glibc-hello`,
  `glibc-hello-via-ldso`, `glibc-hello-list`, `glibc-dlopen`,
  `glibc-tls`, `glibc-gdtls`, `glibc-pthread-tls` --
  dynamically-linked glibc x86_64 binary acceptance through
  `--sysroot` against the staged minimal glibc rootfs under
  `externals/test-fixtures/x86_64-glibc/rootfs/`. The first three
  cover load-time `PT_INTERP` resolution and `ld.so --list`
  introspection. `glibc-dlopen` runs `dlopen("libm.so.6")` plus a
  `dlsym(sqrt)` round-trip to exercise the runtime fresh-`.so`-mmap
  codepath, which is distinct from the load-time path the first
  three probes touch. `glibc-tls` reads and writes two
  initial-exec `__thread` variables (one integer, one pointer) so a
  broken FS-register to `TPIDR_EL0` translation surfaces as a
  value mismatch rather than as a silent skip. `glibc-gdtls`
  `dlopen`s a companion `libgdtls.so` whose `__thread` variable
  must use the general-dynamic model (calls `__tls_get_addr`);
  this is the only probe that exercises that lowering path, which
  the initial-exec probe cannot reach. `glibc-pthread-tls`
  `pthread_create`s a worker thread that reads and writes its own
  `__thread` slot; the probe asserts the worker saw its own
  default value (not the main thread's overwritten marker) and that
  the main thread's slot survives the worker's write, so a broken
  per-thread `TPIDR_EL0` setup on additional threads surfaces as
  isolation failure rather than as a silent crash.

Total: 71 expected passes, 0 expected failures.

### Per-Host Baseline Capture

The matrix runner keys its `elfuse-x86_64` baseline by detected host
SoC class. Two classes matter because `sys_mmap_fixed_high_va` takes
different paths under different IPA widths:

- `apple-m1-m2`: 36-bit native IPA, exercises the overflow-segment
  path. Captured on this codebase against Apple M1 hardware
  (MacBookAir10,1). The seven sub-suites land at 71/0/0.

- `apple-m3-plus`: 40-bit native IPA, exercises the bisected-slab
  path (and the M5 slab-bisection variant). Currently held equal to
  `apple-m1-m2` pending operator capture on real M3+ hardware. When
  that capture lands, only the
  `"elfuse-x86_64:apple-m3-plus|<min_pass>|<max_fail>"` row in the
  `EXPECTED_BASELINES` array in `tests/test-matrix.sh` moves; the
  M1/M2 row stays intact.

- `apple-unknown`: fallback for SoC brand strings the detector does
  not recognise. Inherits the M1/M2 numbers and triggers a one-line
  warning so a new SoC does not silently graft onto an existing row.

Class detection reads `sysctl -n machdep.cpu.brand_string` and matches
against `Apple M1`/`Apple M2` (M1/M2) and `Apple M3`/`Apple M4`/`Apple
M5` (M3+). To exercise the M3+ row from an M1/M2 host (and vice
versa) without changing the detector, set
`MATRIX_HOST_CLASS_OVERRIDE=apple-m3-plus` (or `apple-m1-m2`,
`apple-unknown`) before invoking `tests/test-matrix.sh`.

When the seven sub-suites grow or trim a test, the per-sub-suite
counts in the comment block above `EXPECTED_BASELINES` and the
inventory list above must move in the same commit so the per-host
baseline stays in sync with reality. Each `EXPECTED_BASELINES` entry
is a pipe-separated `mode-key|min_pass|max_fail` triple parsed by
`expected_baseline_get()` in `tests/test-matrix.sh`.

## Test Inventory

The repository contains several layers of validation:

- unit-style guest tests compiled from `tests/*.c`
- shell integration suites such as BusyBox, coreutils, and dynamic-loader tests
- debugger integration tests for the GDB stub
- native macOS HVF checks such as multi-vCPU and RWX validation
- conformance lanes that judge test suites against elfuse and a QEMU
  reference; see `docs/conformance.md`

The quick suite is driven by `tests/driver.sh`, which supports:

- `-f PATTERN` to filter tests
- `-l` to list them
- `-T` for TAP output

Example:

```sh
bash tests/driver.sh -f test-proc
```

## Conformance Tests

`scripts/conformance` runs registered suites on elfuse or QEMU. These are its
public commands:

| Command | Result |
|---------|--------|
| `scripts/conformance suites [--format text\|json]` | List registered suites |
| `scripts/conformance list SUITE [--scope pr\|full] [--backend elfuse\|qemu\|all] [--format text\|json] [--require]` | List canonical case IDs; the default scope is `full` |
| `scripts/conformance run SUITE [--scope pr\|full] [--case ID_OR_GLOB] [--backend elfuse\|qemu\|all] [--jobs N] [--results DIR] [--bootstrap] [--require] [--no-retry] [--dry-run] [-v]` | Run cases; the defaults are the `pr` scope, elfuse, one job, and `build/conformance` |
| `scripts/conformance payload fingerprint SUITE` | Print the payload fingerprint |
| `scripts/conformance payload build SUITE [--force]` | Build the payload |
| `scripts/conformance payload verify SUITE [--fingerprint HASH]` | Verify the payload manifest and files |
| `scripts/conformance selection check SUITE` | Compare selection with the pinned inventory |
| `scripts/conformance selection update SUITE` | Rewrite generated selection |
| `scripts/conformance expectations check [SUITE]` | Validate expectation files |
| `scripts/conformance expectations seed SUITE RESULTS [--reason TEXT] [--write]` | Derive expectation actions from results |
| `scripts/conformance pins check [SUITE] [--ref REF]` | Report pin drift without writing |
| `scripts/conformance pins update SUITE [--ref REF]` | Update a pin |
| `scripts/conformance report RESULTS [--format text\|markdown\|json]` | Read canonical results |
| `scripts/conformance selftest` | Run harness selftests |

Examples:

```sh
scripts/conformance run SUITE --scope full --backend all
scripts/conformance run SUITE --case 'SUITE:GROUP/*' --backend qemu
scripts/conformance report RESULTS --format markdown
```

The Make aliases are `test-conformance-harness`, `test-conformance`,
`test-conformance-full`, `conformance-payloads`, `clean-payloads`, and
`update-pins`. `BACKEND`, `CONF_SCOPE`, `TEST`, `CONF_JOBS`, and
`CONF_RESULTS` configure the run targets. See [conformance.md](conformance.md)
for result, expectation, payload, and suite interfaces.

## Validation Strategy By Change Type

Suggested minimum validation:

| Change area | Recommended validation |
|-------------|------------------------|
| CLI, logging, docs-only build rules | `make elfuse` |
| Filename codec, case-exact walk, sysroot resolvers | `make check` (runs the codec unit tests, name lanes, and byte-exact oracle lane), plus `make test-sysroot-name-soak` for resolver concurrency. A red golden vector in `test-casefold-host` means the on-disk format moved: see `docs/filenames.md` before touching `tests/casefold-vectors.h` |
| General syscall or runtime logic | `make elfuse && make check && make test-matrix-elfuse-aarch64` |
| `/proc`, `/dev`, path, or BusyBox-sensitive behavior | `make elfuse && make check && make test-matrix-elfuse-aarch64` |
| Rosetta hosting, x86_64 dispatch, VZ ioctls, AOT cache | `make elfuse && make test-rosetta-all` |
| Broad behavioral changes | `make elfuse && make check && make test-matrix` |
| Debugger or ptrace flow | `make elfuse && make test-gdbstub` |
