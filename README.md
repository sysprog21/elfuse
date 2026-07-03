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

## Requirements

- macOS on Apple Silicon
- macOS 13 or newer
- Xcode Command Line Tools, `clang`, `codesign`, and GNU `make`
- GNU `objcopy` from Homebrew `binutils`, or `llvm-objcopy`
- `libarchive` and `cJSON` libraries with headers for OCI image support,
  resolved via `pkg-config`: `brew install libarchive cjson` (macOS) or
  `apt-get install libarchive-dev libcjson-dev` (Linux). The `oci`
  subcommand reads tar layers (with gzip/zstd decoding) through
  libarchive and parses JSON manifests. `elfuse oci pull` additionally
  shells out to `skopeo` at runtime (`brew install skopeo`) for registry
  transfers; the rest of the build
  links the system `libcurl` and `zlib` that ship with macOS.
- Hypervisor entitlement: `com.apple.security.hypervisor`

For guest test binaries, the project also expects an AArch64 Linux cross
toolchain. The default paths in `mk/toolchain.mk` target the toolchain layout
used by the repository test harness, but `CROSS_COMPILE` and
`BAREMETAL_CROSS` are overridable.

To run `make check`, install the Homebrew AArch64 embedded toolchain first:

```sh
brew install --cask gcc-aarch64-embedded
```

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
  Rosetta, dynamic linking via `--sysroot`, and attaching `gdb` /
  `lldb` to the built-in stub.
- [docs/testing.md](docs/testing.md): build prerequisites, the
  `make check` flow, the QEMU and Rosetta cross-check matrices, and
  fixture handling.
- [docs/internals.md](docs/internals.md): canonical technical
  reference -- runtime lifecycle, HVF constraints, EL1 shim and HVC
  protocol, page-table splitting, syscall translation tables, threads
  / futex, fork / clone IPC, signals, ptrace, and the GDB stub.

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

## License

Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2026 elfuse contributors  
Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
