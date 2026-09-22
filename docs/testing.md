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
make verify
make lint
make clean
```

What they do:

- `make elfuse`: build and sign `build/elfuse`
- `make check`: fast elfuse-internal gate. Runs, in order:
  - `scripts/check-syscall-coverage.py` so any new `dispatch.tbl`
    entry without a direct or aliased test reference fails the build
  - `scripts/check-eintr-contract.py` so a new interruptible wait fails
    the build until it states whether it may be restarted (`forbids`,
    `restartable`, or `not-a-wait`), with the `forbids` claims checked
    against the source
  - `scripts/check-lock-order.py` so a new file-scope `pthread_mutex_t`
    or `pthread_rwlock_t` that the lock-ordering block at the top of
    `src/syscall/internal.h` does not name fails the build. Membership
    only: whether the lock belongs in the ordered list or the leaf list
    stays a judgement for review
  - `scripts/check-atomics.py` so a C11 atomic call written without its
    `_explicit` form, or a `__atomic_*` / `__sync_*` builtin, fails the
    build. Plain-operator access to an `_Atomic` object needs the
    declarations resolved and stays a review question
  - `scripts/check-ascii.py` so a source file carrying non-ASCII outside
    the comment-diagram set fails the build
  - `scripts/check-svc-tails.py` so an HVC #5 return tail cannot reach EL0
    without the X7 ptrace test
  - `scripts/check-skill-refs.py` so a path, make target, or docs section
    a skill names that no longer resolves fails the build
  - `scripts/check-proof-targets.py` so a header added under `src/proved/`
    with no proof target fails here rather than on the branch later. It
    asks make for the target list, which is the point: a `VERIFY_<T>_SRC`
    block written below the `:=` that builds `VERIFY_TARGETS` parses fine
    and generates no rule
  - the two harness self-tests, `test-config` (that `tests/test-config.sh`
    keeps its CLI mode separate from its sourced mode) and `test-runner`
    (the shared shell runner's output matching and exit-status checks), so
    the harness is known good before any lane leans on it
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
- `make verify`: every Frama-C WP proof target, one `frama-c` process each
  and parallel by default (`VERIFY_JOBS=1` for serial). Each target names a
  function set and discharges its obligations under `-wp-rte`; `mk/verify.mk`
  is the target list and records the data model and memory model each one
  assumes. Needs `opam install frama-c` plus `why3 config detect`; without
  the latter WP aborts with "Prover not found" instead of reporting unproved
  goals. `make verify-<name>` runs one target
- `make verify-mutants`: assert every proof target rejects a known-broken
  source, so a contract whose clauses do not bite fails. `MUTANT_TARGET=<name>`
  narrows it to one target, `MUTANT_SINCE=<ref>` to what a branch touched, and
  `MUTANT_JOBS=N` overrides the one-per-core default
- `make check-contracts`: rebuild with `-DELFUSE_CONTRACT_ASSERT` so the
  expressible `proved/gva.h` preconditions are checked on every call the suite
  makes. Separate from `make check` because those checks sit on the
  `guest_read` / `guest_write` hot path
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

The quick suite is driven by `tests/driver.sh`, which supports:

- `-f PATTERN` to filter tests
- `-l` to list them
- `-T` for TAP output

Example:

```sh
bash tests/driver.sh -f test-proc
```

## Fault Injection And Recorded Rows

Several failures these lanes have to pin cannot be provoked from a test: a
`malloc` coming back NULL part-way through a backing listing, a `readdir` that
fails part-way through a directory elfuse itself materialized, a slot replaced
inside a window that is sub-microsecond wide unaided, and, on the usbdevfs fd,
each of the three ways an open can fail before it returns. Each has an
environment hook, read once and with no effect at all when unset:

| Variable | Effect | Driven by |
|----------|--------|-----------|
| `ELFUSE_DIR_BACKING_FAULT=N` | the union drain fails with `ENOMEM` once it has buffered N names | `test-dir-backing-drain-error` |
| `ELFUSE_DIR_PRIMARY_READ_FAULT=N` | `readdir` on the synthetic stream fails with `EIO` after N entries | `test-dir-primary-read-error` |
| `ELFUSE_DIR_UNION_BACKING_DELAY_US=N` | widens the window between pinning a directory stream and looking its backing up | `test-dir-union-fd-reuse` |
| `ELFUSE_FD_IDENTITY_WINDOW_US=N` | widens the window between reading a descriptor's stamp and pinning its host fd | `test-fstatfs-fd-identity` |
| `ELFUSE_USBDEV_OPEN_FAULT=info\|blob\|pipe` | fails one step of a usbdevfs open: the model lookup or the descriptor copy with `ENOMEM`, the readiness pipe with `ENFILE` | `test-usbdev-faults` |
| `ELFUSE_USBDEV_PUBLISH_DELAY_US=N` | widens the window between `fd_alloc` publishing a usbdevfs fd and the side table binding it, where a close finds no entry | `test-usbdev-faults` |
| `ELFUSE_USBDEV_RETIRE_DELAY_US=N` | widens the window between the side table binding a usbdevfs fd and the open's recheck, where a close can reap the entry and a sibling open can take its slot | `test-usbdev-faults` |
| `ELFUSE_USBDEV_REAP_DELAY_US=N` | widens the window between the fd-table snapshot a `REAPURB` pass takes and the side-table entry it settles readiness on, where a close and reopen can swap the description underneath it | `test-usbdev-faults` |

`ELFUSE_USB_FIXTURE` is the same shape pointing at enumeration rather than
failure: it stands a deterministic synthetic USB tree up in place of whatever
IOKit reports, so the lanes below have devices to walk on any host.
`ELFUSE_USB_FIXTURE=overflow` stands up 129 address-less devices on one bus for
the `devnum` cap. `ELFUSE_USB_FIXTURE=badifnum` adds one device whose only
interface declares `bInterfaceNumber` 200: every byte is well formed and the
range is the field's own, but nothing anyone can plug in emits it, so it is the
only way to reach the paths that index by that number.

The lanes these drive:

| Lane | Property |
|------|----------|
| `test-usb-sysfs-matrix` | every entry point against every class of name `/sys` and `/dev/bus` can hold |
| `test-getdents64-small-buf` | a buffer that cannot take the next entry reports rather than ending, and the entry it could not take comes back |
| `test-dir-backing-drain-error` | a union listing that lost its backing half is reported, not ended |
| `test-dir-primary-read-error` | the same on the synthetic half |
| `test-dir-union-fd-reuse` | a walk answers for the directory it pinned, not for the fd number |
| `test-dir-union-alias` | every route to a second fd on one description shares one position and one union state |
| `test-dir-fd-budget-union` | a union directory fd costs one host descriptor, like a plain one |
| `test-fstatfs-fd-identity` | `fstatfs` answers for the descriptor it pinned, not for the fd number |
| `test-usbdev-faults` | an interface number wider than the table that indexes it, each open-time failure reported as itself, a close inside the fd publish window leaking nothing, and a reap that answers for the description it snapshotted rather than the fd number |
| `test-usbdev-ioctl-departed` | every usbdevfs ioctl this layer names, on a device that has gone: the return, the `errno`, the stamp on the fd that asked and the stamp on a peer fd, against the Linux answer recorded for that request |

Some lanes carry rows that are recorded rather than asserted, and print as
`XFAIL`. An `XFAIL` row is a measured Linux value the build knowingly does not
meet: it is neither a pass nor a failure, it does not turn the lane red, and the
value elfuse gives today is carried beside it so that a departure from either
number shows up as a diff in the lane's output. The alternative -- deleting the
row -- is what lets a known divergence become an unknown one.

`test-usb-sysfs-matrix` records its `escape-syn` column that way: a `..` chain
walking through the synthetic subtree and back out cannot be resolved here,
because the host walk has to traverse a `/sys/bus/usb` that exists only inside
the layer. `test-dir-union-alias` records its fork cross-close rows: a child
whose parent closes its copy of the fd before the backing has been drained
answers with its primary alone, because the backing half belongs to a stream
that has gone. Both rows are load-bearing in pairs -- neither number alone
separates the answers the site could give -- so both are printed.

`test-usbdev-ioctl-departed` is the same idea with the recording moved out of
the lane and into data. Its rows are generated from
`tests/usbdev-ioctl-departed.tbl`, one per usbdevfs ioctl, and a row that
diverges from Linux carries both tuples: the lane fails if the elfuse answer
stops matching the recorded one, and fails just as loudly if it starts matching
Linux's, because an XFAIL nobody notices closing is a row that should have been
retired. The generator refuses to emit at all unless every ioctl
`usbdev_ioctl` dispatches has a row, so the recording cannot fall behind the
surface it describes.

USB-layer coverage is split by what it needs. `test-uevent-socket` needs no
hardware and runs in the matrix like any other unit test. The two usbdevfs
lanes need no hardware either, and neither of them runs in the matrix:
`test-usbdev-ioctl` drives the fd against `ELFUSE_USB_FIXTURE`, whose devices
are modeled but have no IOKit service behind them, so every answer it asserts
is that model's and the reference kernel has nothing to adjudicate; and
`test-usbdev-urb-host` is a native macOS binary over
`src/syscall/usbdev-urb.h`, the URB bookkeeping that is decided before any
transfer -- the disconnect-watch refcon, `SUBMITURB`'s argument gate, the
transferred-count clamp, the `ZERO_PACKET` predicate and the endpoint start
gate -- and sits in `NATIVE_TESTS` (`mk/config.mk`), so it is never
cross-compiled for a guest runner at all. Both run under `make check` and
nowhere else, which is what `grep usbdev tests/test-matrix.sh` says: it is
empty. The comment above `SANITIZER_SECTIONS` in `mk/tests.mk` records the same
split from the other side. That header exists because the fixture stops at the
argument gate: the async engine's first review found five defects in code no
lane executed, and the arithmetic half of it is testable on any machine.

`test-usbdev-urb-loopback` covers the other half. IOKit publishes no loopback
device, so the fixture becomes one: `ELFUSE_USB_FIXTURE=loopback` substitutes
for the two IOKit COM vtables and for nothing above them (see
[internals.md](internals.md#testing-the-engine-without-hardware)), which puts
submit, the per-endpoint queue, the completion callback on the event thread,
`DISCARDURB`, `REAPURB` blocking and non-blocking, poll and epoll readiness,
the `CAP_REAP_AFTER_DISCONNECT` drain and the `ZERO_PACKET` trailing packet
under assertion on any machine. The `wedge` script step adds the transfer
whose abort outlives the engine's 2 s drain deadline, which is what puts the
orphaning path and the two ioctls that refuse on it under assertion too;
nothing else in the vocabulary reaches them, because every other outstanding
transfer answers an abort at once. It is also what times the drain, from both
ends: the lane asserts that a `REAPURBNDELAY` which owes the post-disconnect
kill issues its aborts and answers without waiting for them, and that a loop of
them still reaches `ENODEV` a drain deadline later rather than spinning on
`EAGAIN` for as long as the wire withholds the abort. The elapsed time is the
whole measurement in both. A `terminate` with `wIndex` bit 1 tears the claimed
interface's pipes down and changes nothing else, so `GetPipeProperties` alone
answers `NoDevice`: that is the device vanishing between the `GetNumEndpoints`
that sizes a pipe map and the calls that fill it in, and it is the only way in
the vocabulary to reach a half-built map. Bit 2 is the same idea for the one
answer only an abort can give: `AbortPipe` and `USBDeviceAbortPipeZero` return
`NoDevice` and cancel nothing, which is what a `DISCARDURB` meets when the user
client behind its handle has gone. It is its own fact rather than a consequence
of `terminate`, because a disconnect drain issues aborts and IOKit lands those:
tying the two would leave every `never` transfer outstanding for ever and no
drain would ever finish.

Two things the lane asserts are not guest-visible at all, so the fixture counts
them and the guest reads the counts back through a control request. One so far:
device handles the layer released while the fixture still owned a transfer on
the default control pipe. On real IOKit that is a use-after-free and here it is
not -- the fixture frees a COM wrapper nothing dereferences again -- so the
count is what stands in for it, and it is read on a later fd because the
release happens at close.

One scenario runs in a process of its own (`test-usbdev-urb-loopback
terminate-race`): it terminates the device while an fd is closing, and every
other scenario still needs that device afterwards. What it asks is whether a
terminate delivered inside a close's two-second drain can stamp a guest fd
number that a sibling has already taken. Two fds on one node carry the other
cross-fd assertion, that a disconnect one of them provokes reaches the one that
never touched the device, and a budget filled with URBs that will not complete
carries the third, that a synchronous `CONTROL` is charged against the same
allowance a synchronous `BULK` is. `test-usbdev-ioctl-loopback` re-runs the
fd-contract lane with that device present, which is the check that the seam did
not reach a path it is not supposed to touch.

`test-usbdev-ioctl-departed` uses the same device for the one thing no other
lane can arrange: a device that leaves while fds are open on it. It terminates
the fixture's device once and then drives every usbdevfs ioctl the layer
implements, one fresh fd per request, asserting the return, the `errno`, the
poll revents on the fd that asked and the revents on a second fd open on the
same node. Three runs, because the first correct `ENODEV` stamps every fd on
the node: the requests that need a claim taken before the device left get a
process each. What the lane may assert is not written in it --
`scripts/gen-usbdev-ioctl-departed.py` reads the ioctl surface out of
`usbdev_ioctl`'s dispatch and joins it against
`tests/usbdev-ioctl-departed.tbl`, so an ioctl added to the layer fails `make
check` until somebody records what Linux answers for it on a departed device.
`make check-usbdev-departed` runs that join by itself.

The loopback lanes run `build/elfuse-loopback`, which they build by re-entering
make with `USB_LOOPBACK_FIXTURE=1`. That variable is also what names the
binary: `mk/config.mk` points `ELFUSE_BIN` at `$(ELFUSE_LOOPBACK_BIN)` for the
fixture flavor, so the two flavors never write the same path and `build/elfuse`
cannot be a stale copy of the fixture build. It could before, and the flavor
stamp in `mk/common.mk` had nothing to say about it, being keyed on `CFLAGS`
while the switch changes `SRCS`: `make clean; make elfuse; make
USB_LOOPBACK_FIXTURE=1 elfuse; make elfuse` printed `Nothing to be done` and
left `nm build/elfuse` finding `_usbdev_fixture_lock` until the next `make
clean`. That was measured before the split and cannot be re-measured after it;
the dated byte counts are in
[internals.md](internals.md#testing-the-engine-without-hardware).
`.ci/check-usb-fixture-bin.sh` asks make for both paths and fails if they are
the same; `make check` runs it. The model is therefore not in `build/elfuse`,
and so not in anything shipped: see
[internals.md](internals.md#testing-the-engine-without-hardware).

What the loopback cannot answer stays on the board, and the list is short and
worth keeping honest: real timing, NAKs, maxpacket segmentation, DMA alignment
and throughput; that IOKit really delivers completions on the runloop, and the
`IODispatchCalloutFromCFMessage` opacity that motivates the URB record's atomic
owner (a timer callout is fully visible to ThreadSanitizer, so that
justification is board-only); exclusive-access arbitration and kernel-driver
binding, so `GETDRIVER` and `DISCONNECT_CLAIM` against a real driver; a real
`SET_CONFIGURATION`, `SET_INTERFACE` pipe renumbering and port `RESET`; that a
device actually receives the zero-length packet, as opposed to elfuse emitting
it under the right predicate; and a physical unplug mid-transfer. Two of the
engine's own answers are board-only for the same reason, and breaking either
of them leaves the lane green: the `ZERO_PACKET` write's dropped `async_lock`
and its bounded timeout only matter against an endpoint that NAKs, and the
fixture answers a zero-length write immediately and ignores both timeout
arguments; and so is the bystander window `ep_aborting` shuts, because the
fixture retargets an aborted transfer's timer under its own lock and can never
start a follower into an abort that is still running. The guest probes for
those live out of tree. A hardware-dependent check that does move
in must be gated on an environment variable naming the device and must skip
with a stated reason when it is absent -- a skip is not a pass, and the
skip lists above are the model: deliberate, explained, and checked.

## Validation Strategy By Change Type

Suggested minimum validation:

| Change area | Recommended validation |
|-------------|------------------------|
| `cmd/oci/` | `make oci-lint && make oci-test` |
| CLI, logging, docs-only build rules | `make elfuse` |
| Filename codec, case-exact walk, sysroot resolvers | `make check` (runs the codec unit tests, name lanes, and byte-exact oracle lane), plus `make test-sysroot-name-soak` for resolver concurrency. A red golden vector in `test-casefold-host` means the on-disk format moved: see `docs/filenames.md` before touching `tests/casefold-vectors.h` |
| General syscall or runtime logic | `make elfuse && make check && make test-matrix-elfuse-aarch64` |
| `/proc`, `/dev`, path, or BusyBox-sensitive behavior | `make elfuse && make check && make test-matrix-elfuse-aarch64` |
| Rosetta hosting, x86_64 dispatch, VZ ioctls, AOT cache | `make elfuse && make test-rosetta-all` |
| Broad behavioral changes | `make elfuse && make check && make test-matrix` |
| Debugger or ptrace flow | `make elfuse && make test-gdbstub` |
| ACSL contracts, `src/proved/`, `mk/verify.mk`, the mutation harness | `make verify && make verify-mutants`, in that order and never beside a runtime lane: both fan out, and the timing lanes fail under the load they create. Add `make check` only when the change touches code rather than annotations |

## OCI Image CLI

The Go CLI has separate format, vet, and race-test targets:

```sh
make oci-lint
make oci-test
ELFUSE_OCI_NETTEST=1 make oci-test
```

The default suite constructs image data in temporary stores and covers the
CLI, store, and unpack without a registry. `ELFUSE_OCI_NETTEST=1` adds a pull
from Docker Hub.
