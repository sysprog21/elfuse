# elfuse

Run Linux ELF binaries directly from the macOS shell -- no Docker, no
full VM image, no daemon. `elfuse` is a process-scoped Linux user-space
runtime: each guest runs inside a lightweight Hypervisor.framework VM
owned by the `elfuse` process itself, and Linux syscalls are translated
to macOS behavior in host-side handlers rather than served by a real
Linux kernel.

Native aarch64-linux executes directly on the CPU. x86_64-linux
executes through Apple's embedded Rosetta translator hosted inside the
same VM; the architecture is auto-detected from the ELF header. Both
static and dynamically linked guests are supported, with the dynamic
linker resolved against an external sysroot via `--sysroot`.

## Features

- Single native macOS binary (~560 KiB signed), no daemon and no disk
  image
- Millisecond-scale VM startup; per-syscall overhead is microseconds
- Native Apple Silicon execution through Hypervisor.framework
- Static and dynamically linked `aarch64-linux` ELF binaries
- Static and dynamically linked `x86_64-linux` ELF binaries via Apple
  Rosetta (auto-detected from the ELF header, opt out with
  `--no-rosetta`)
- Linux-style processes, threads (1:1 with HVF vCPUs, up to 64),
  signals, timers, futexes (incl. PI ops), and polling
- Guest reads and writes the macOS filesystem directly; no overlay or
  volume mount layer
- Linux byte-exact filename semantics under `--sysroot`, including
  case-colliding names on the default case-folding APFS (see
  [docs/filenames.md](docs/filenames.md))
- Synthetic `/proc` and selected `/dev` emulation for user-space probes
- Guest-internal FUSE: `/dev/fuse` and `mount("fuse")` work without
  macFUSE / FUSE-T / FSKit
- Built-in GDB Remote Serial Protocol stub usable from `gdb` or `lldb`
- Self-contained test matrix that cross-checks elfuse against QEMU
  and exercises a separate Rosetta acceptance suite

## Positioning

`elfuse` is intentionally narrow. It runs single Linux binaries (and
their `fork`/`exec` children) with minimal overhead; it does not host a
Linux kernel, namespaces, cgroups, or kernel modules. For workloads
that need full kernel features, container orchestration, or systemd,
prefer a full VM tool (Lima, UTM, OrbStack) or Docker Desktop. For
single-binary tooling, language runtimes, test harnesses, and
debugger-driven workflows, `elfuse` removes the disk-image and
boot-time overhead those tools impose.

## Why C

`elfuse` is C11 plus a small amount of aarch64 assembly. In short:

- Most of the hazard sits inside the safety boundary, not outside it. Guest
  memory is an `mmap`-ed slab the guest rewrites from another vCPU thread, so
  host access already runs through bounds-checked accessors (`guest_ptr`,
  `guest_read`, `guest_write`). Rust would enforce that discipline rather
  than leave it to convention, which is a real gain, but the checks inside
  those accessors are the same ones to get right.
- The defects that surface here are arithmetic and design errors, not
  memory-safety errors. An overflow-saturated `load_max` in `src/core/elf.c`
  wraps once the PIE load base is added in `src/syscall/exec.c`, pushing a
  rejection past the `execve` point of no return. Rust's `+` wraps in release
  builds too; catching it takes an explicit checked add either way.
- What guards the memory-safety side is language-independent and already
  gates CI: `cppcheck`, `clang-tidy`, `scan-build`, Infer, and a runtime
  matrix under ASAN, UBSAN, and TSAN. That catches such defects after the
  fact rather than excluding them by construction, which is the honest cost
  of the choice.
- The host surface is nearly all C ABI: Hypervisor.framework, Mach, pthreads,
  macOS syscalls, `SCM_RIGHTS`, and hosting Apple Rosetta. The EL1 shim is
  aarch64 assembly under any host language.

Longer version in [docs/internals.md](docs/internals.md#language-choice).

## Requirements

- macOS on Apple Silicon
- macOS 13 or newer
- Xcode Command Line Tools, `clang`, `codesign`, and GNU `make`
- GNU `objcopy` or `llvm-objcopy`
- Hypervisor entitlement: `com.apple.security.hypervisor`

To build only (`make elfuse`) without running tests, just the
Xcode Command Line Tools and `objcopy` (`brew install binutils`) suffice.

For guest test binaries, the project also expects an AArch64 Linux cross
toolchain. The default paths in `mk/toolchain.mk` target the toolchain layout
used by the repository test harness, but `CROSS_COMPILE` and
`BAREMETAL_CROSS` are overridable.

See
[docs/testing.md](docs/testing.md#build-requirements) for toolchain setup guide.

## Quick Start

```sh
git clone https://github.com/sysprog21/elfuse
cd elfuse
make elfuse
make test-busybox
build/elfuse build/busybox
```
Replace `build/busybox` with an aarch64-linux or x86_64-linux executable.
The guest architecture is auto-detected from the ELF header.

For dynamically linked guests:

```sh
build/elfuse --sysroot /path/to/sysroot ./path/to/program
```

For x86_64-linux guests, Rosetta is on by default. To disable:

```sh
build/elfuse --no-rosetta ./path/to/aarch64-only-binary
```

For early debugging:

```sh
build/elfuse --gdb 1234 --gdb-stop-on-entry ./path/to/program
```

`--gdb` is rejected for x86_64 guests because the stub serves the
aarch64 view Rosetta produces, not the original x86_64 architectural
state.

The build signs `build/elfuse` before use. Override the signing identity with
`SIGN_IDENTITY="Developer ID ..."` when needed.

## Documentation

- [docs/usage.md](docs/usage.md): command-line options, x86_64 via
  Rosetta, dynamic linking via `--sysroot`, attaching `gdb` / `lldb` to
  the built-in stub, and running the conformance suites.
- [docs/testing.md](docs/testing.md): build prerequisites, the
  `make check` flow, the QEMU and Rosetta cross-check matrices, and
  fixture handling.
- [docs/conformance.md](docs/conformance.md): the conformance harness,
  expectations, payloads, and CI workflow.
- [docs/filenames.md](docs/filenames.md): how a guest filename becomes a
  name on disk and back: case folding and normalization on the sysroot
  volume, the escape encoding, and the length limits both systems impose.
- [docs/internals.md](docs/internals.md): canonical technical
  reference -- runtime lifecycle, HVF constraints, EL1 shim and HVC
  protocol, page-table splitting, syscall translation tables, threads
  / futex, fork / clone IPC, signals, ptrace, and the GDB stub.
- [CONTRIBUTING.md](CONTRIBUTING.md): the coding style, the formatters
  and what each gate enforces, and the commit-message rules.

## Build And Validation

Most common targets:

```sh
make elfuse        # build and codesign build/elfuse
make check         # quick unit suite + BusyBox applet smoke
make test-gdbstub  # debugger integration
make test-matrix   # cross-check elfuse against QEMU on the same corpus
make lint          # clang-tidy
```

`make check` is the recommended pre-commit gate. `make test-matrix` is the
recommended gate for changes touching procfs, dynamic linking, networking,
or process semantics. `make test-rosetta-all` covers the x86_64 acceptance
suites in isolation. See [docs/testing.md](docs/testing.md) for the full
target list, fixture flow, and validation-by-change-type guidance.

The first `make` in a fresh clone installs Git hooks that run the same checks
CI does, at commit and push time instead of after: staged formatting, comment
reflow, banned APIs, whitespace and conflict markers, and the commit-message
rules in [CONTRIBUTING.md](CONTRIBUTING.md). A missing local formatter warns
rather than blocks, and a hook you already wrote is never replaced.
`make uninstall-hooks` removes them, `make install-hooks` puts them back. They
do not replace `make check`.

`make test-conformance` judges each suite's pull-request subset against
checked-in expectations. See [docs/usage.md](docs/usage.md#conformance-testing).

## Limitations

`elfuse` runs single Linux user-space processes (and their `fork` /
`exec` children). It is not a Linux kernel.
That framing shapes both what it does and what it explicitly will not
do.
- Linux kernel features that have no user-space-syscall analog:
  namespaces, cgroups, kernel modules, eBPF, `io_uring`, KVM, perf
  events.
- Intel Macs. Apple Silicon only (M1 and later).
- Hosting a VM from inside a guest. The guest cannot use HVF or KVM.
- One guest process tree per `elfuse` host process. HVF allows one VM
  per host process; Linux-style `fork` is implemented by
  `posix_spawn`-ing a fresh `elfuse` host process and transferring
  state (see [docs/internals.md](docs/internals.md)).
- Up to 64 concurrent guest threads per VM (`MAX_THREADS = 64`).
- Around 213 syscalls implemented; anything outside
  `src/syscall/dispatch.tbl` returns `-ENOSYS` rather than silently
  succeeding.
- `FUTEX_LOCK_PI` and friends behave as plain mutex acquire / release;
  true priority-inheritance scheduling is not modeled.
- `sched_setaffinity` is honored as a no-op (returns the all-CPUs
  mask); the host scheduler picks the actual CPU.
- `/proc`, `/dev`, and mount data are synthetic compatibility views,
  not host pass-throughs.
- `uname` and `/proc/version` report Linux 6.18 LTS, a floor for
  version-gated userspace; `src/syscall/dispatch.tbl` states what is
  implemented.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. It is the tracked style
guide: the C conventions this tree actually follows, which formatter
owns which part of a file, what CI gates and what it does not, and the
seven commit-message rules the log is written to.

Two things settle most review comments before they are written:

```sh
make indent        # apply every formatter, comment reflow included
make check-format  # verify without rewriting
```

File an issue before a substantial change, so the design discussion
happens before the effort does. Typo fixes, small refactors, and
comment or documentation edits need no issue.

## License

Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2026 elfuse contributors  
Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
