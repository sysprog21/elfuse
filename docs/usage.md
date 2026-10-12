# Using elfuse

This document covers the command-line interface, common launch patterns,
dynamic linking through `--sysroot`, and debugger attachment.

## Command-Line Synopsis

```sh
build/elfuse [options] <elf-path> [args...]
```

Supported user-facing options:

| Option | Meaning |
|--------|---------|
| `-h`, `--help` | Print built-in usage help |
| `-V`, `--version` | Print the build version and exit |
| `-v`, `--verbose` | Enable syscall-level and loader diagnostics |
| `-t`, `--timeout N` | Per-iteration vCPU watchdog, in seconds (default `10`, `0` disables) |
| `--sysroot PATH` | Resolve guest absolute paths under `PATH`, falling back to the host for paths it does not hold |
| `--create-sysroot PATH` | Provision a case-sensitive APFS sparsebundle mounted at `PATH`, then use it as the sysroot |
| `--no-rosetta` | Disable the x86_64-via-Rosetta translator (also `ELFUSE_NO_ROSETTA=1`) |
| `--fakeroot` | Start the guest as uid/gid 0 with full emulated capabilities (also `ELFUSE_FAKEROOT=1`) |
| `--gdb PORT` | Listen for a GDB RSP client on `PORT` (aarch64 guests only) |
| `--gdb-stop-on-entry` | Stop before the first guest instruction |
| `--user UID[:GID]` | Run the guest as `UID`, and `GID` when given (defaults to `UID`). Numeric only |
| `--workdir DIR` | Guest-absolute initial working directory, resolved under `--sysroot` |
| `--env KEY=VALUE` | Set a guest environment variable. Repeatable; a bare `KEY` imports the host value |
| `--clear-env` | Start from an empty environment; only `--env` entries apply |
| `--` | End `elfuse` option parsing; remaining tokens are guest argv |

`ELFUSE_FAKEROOT_EXEC` has no flag form. It names one executable, by absolute
path, whose `execve` enters fakeroot mode, so a guest can run unprivileged and
raise privilege the way `sudo` does rather than paying for root over the whole
session. Two properties are worth knowing before using it:

- The match is on file identity, not on the pathname. Any spelling that reaches
  the marked executable elevates -- guest path or host path under `--sysroot`,
  through symlinks, relative or not -- and a spelling that reaches some other
  file does not. Replacing the file at that path replaces what elevates.
- Elevation is never dropped. The marked image, everything it `exec`s
  afterwards, and everything it forks all stay root. It is a `sudo`-shaped
  transition for a process tree, not a per-command one.

Unset, which is the default, no exec ever elevates. A value that is not an
absolute path is rejected at startup rather than ignored.

`--timeout` is a run-loop watchdog. It does not cap total process runtime. It
only bounds a single `hv_vcpu_run()` iteration before the host regains control,
which is what allows host-side timers and signals to be observed promptly.
Setting `--timeout 0` disables this watchdog for long-running CPU-bound guests.

## Guest Identity, Working Directory, And Environment

`--user`, `--workdir`, `--env`, and `--clear-env` select what the guest starts as,
where it starts, and what it sees in its environment. A contradictory `--user`
request or a malformed `--env` entry is rejected before the VM is created, and
`--workdir` is resolved during bring-up, before the first guest instruction, so
a bad request fails with a diagnostic instead of launching a guest that runs as
something other than what was asked for.

`--user UID[:GID]` sets the identity the guest reports through `getuid` and
`getgid`. It does not change the host process credentials: elfuse translates the
guest's syscalls, so the number the guest sees is elfuse's to choose. The spec is
numeric, and a bare `UID` sets the group to the same value.

`--fakeroot` cannot be combined with a non-root `--user`. Fakeroot starts the guest
as uid/gid 0, and the setuid permission check grants every id switch on that basis,
so a guest that reported an unprivileged uid could still call `setuid(0)` at will.
Both halves must be root, which makes `--fakeroot --user 0:0` valid and
`--fakeroot --user 0:1000` a refusal.

`--workdir DIR` takes a guest-absolute path and is rejected otherwise. A relative
path would be resolved against the host working directory, silently starting the
guest outside the intended tree. The path is translated through `--sysroot` and
then entered, the same way a guest `chdir` into a real directory is handled,
with one launch-time restriction: the resolved directory must sit inside the
sysroot. For a path the sysroot does not hold, a guest syscall falls back to
the host, but a workdir that exists only on the host would start the guest
outside the requested tree, so the launch refuses it. FUSE-mounted,
`/proc`-virtual, and `/dev/shm` directories are not supported through this
flag: a guest `chdir` into `/dev/shm` does two things this flag does not (it
refuses a symlink leaf, and it keeps `getcwd` reporting the `/dev/shm`
spelling rather than the backing location).

`--env` follows `docker run -e`. It is repeatable: `KEY=VALUE` replaces that
variable when it is already present and appends it otherwise, while a bare `KEY`
imports the host's value for `KEY`. Unset and set-to-empty are distinct: a name
the host does not set is skipped rather than imported as an empty value, while a
host `KEY=` imports as `KEY=`. An empty variable name is rejected. Given neither
`--env` nor `--clear-env`, the guest inherits the host environment unchanged.
`--clear-env` starts from nothing, leaving only what `--env` puts back.

## Common Launch Patterns

Run a statically linked guest binary:

```sh
build/elfuse ./build/test-hello
```

Run with verbose tracing:

```sh
build/elfuse --verbose ./guest-program arg1 arg2
```

Pass guest arguments that begin with `-`:

```sh
build/elfuse -- ./guest-program --guest-flag
```

The guest's exit status is propagated as the `elfuse` exit status, so
`elfuse` composes with shell pipelines, `make`, CI scripts, and
anything else that inspects `$?`.

### Worked Examples

The guest reads and writes the host filesystem directly (no overlay,
no volume mount), so file arguments are just file arguments. Under
`--sysroot` the temporary directories are the exception; see
[Dynamic Linking And Sysroots](#dynamic-linking-and-sysroots).

Run a Linux static `jq` against a host JSON file:

```sh
build/elfuse ./jq-aarch64-static '.name' /tmp/data.json
```

Drop into an interactive `bash` session against a musl sysroot:

```sh
build/elfuse --sysroot ./aarch64-musl-sysroot \
    /path/to/aarch64-linux/bin/bash
```

Run a Linux `sqlite3` against a host database file:

```sh
build/elfuse ./sqlite3-aarch64-static /tmp/mydata.db \
    'SELECT name FROM sqlite_master WHERE type = "table";'
```

Run an x86_64 Linux binary (architecture is auto-detected; Rosetta
hosts the translator):

```sh
build/elfuse ./hello-x86_64-static
```

## x86_64-via-Rosetta

Statically linked `x86_64-linux` ELFs run through Apple's embedded
Rosetta translator hosted inside the guest VM. The architecture is
auto-detected from the ELF header, so the same `elfuse` invocation
works for both aarch64 and x86_64 inputs:

```sh
build/elfuse ./x86_64-static-binary
```

Rosetta is on by default. To force the aarch64-only path (or to
verify that a binary really is aarch64), pass `--no-rosetta` or
export `ELFUSE_NO_ROSETTA=1`:

```sh
build/elfuse --no-rosetta ./aarch64-program
```

Both statically and dynamically linked x86_64 binaries are supported.
Dynamic guests need an x86_64-linux sysroot:

```sh
build/elfuse --sysroot /path/to/x86_64-sysroot ./x86_64-dynamic-binary
```

The sysroot must contain the requested dynamic linker
(typically `/lib64/ld-linux-x86-64.so.2` for glibc, or
`/lib/ld-musl-x86_64.so.1` for musl) and any shared libraries the
guest opens. elfuse loads Rosetta into the VM and lets the translator
read the guest ELF; the translated x86_64 dynamic linker then maps
the interpreter and shared libraries through the sysroot like any
other guest process. Runtime `dlopen` and per-thread TLS are
exercised by `tests/test-rosetta-glibc.sh`.

Notes:

- `--gdb` is rejected for x86_64 guests: the stub serves the aarch64
  view Rosetta produces, not the original x86_64 architectural state.
- The CoW fork fast path is disabled for Rosetta because HVF caches
  the host VA-to-PA mapping at `hv_vm_map` time.
- Two Rosetta-internal divergences are documented and not papered
  over: `SA_RESETHAND` is shadowed by Rosetta's own signal-handler
  state, and `clone(..., CLONE_SETTLS, tls=0, ...)` can hang.

The first x86_64 launch may pause briefly while the AOT cache under
`$HOME/.cache/elfuse-rosettad/` warms up; subsequent launches reuse
the SHA-256-keyed translations.

## Dynamic Linking And Sysroots

Dynamic Linux guests need a sysroot that contains the expected interpreter and
shared libraries. `elfuse` reads `PT_INTERP`, loads the requested interpreter
from the supplied sysroot, and redirects guest absolute-path opens to that tree,
falling back to the host filesystem for paths the sysroot does not hold.

Example:

```sh
build/elfuse --sysroot /path/to/sysroot ./hello-dynamic
```

This model supports both musl and glibc guest environments as long as the
expected interpreter path (for example `/lib/ld-musl-aarch64.so.1` or
`/lib/ld-linux-aarch64.so.1`) exists inside the sysroot.

Practical notes:

- The sysroot is consulted for guest absolute paths; relative paths resolve
  from the guest working directory, and inside the sysroot they receive the
  same byte-exact name semantics as absolute ones.
- `/tmp`, `/var/tmp`, and any `.ccache` directory are backed by the sysroot
  alone. A guest's temporary files go there so they cannot collide on a
  case-insensitive host `/tmp`, and every operation on those paths, including
  `stat`, `open`, and directory listings, addresses the same place. Host files
  under those directories are therefore invisible to the guest, and a guest
  program or interpreter stored there cannot be loaded; pass one from anywhere
  else.
- `..` stops at the guest's root as it does on Linux, so `/..` and
  `/../etc/hosts` name `/` and `/etc/hosts` inside the sysroot. The directory
  the sysroot itself lives in is not reachable from the guest.
- The sysroot setting is preserved across guest `fork` and `execve`, so spawned
  children see the same view of the filesystem.
- On case-insensitive macOS volumes, `elfuse` keeps Linux's byte-exact name
  semantics: a lookup whose spelling differs from the on-disk entry only by
  case or Unicode normalization form reports `ENOENT`, and a name the volume
  cannot store as itself is held under an escaped `.ef=<payload>` spelling the
  guest never sees. Guest names keep their full 255 bytes either way.
  [docs/filenames.md](filenames.md) describes the model.
- A sysroot holding `.ef_<token>` entries plus a `.elfuse_case_index` file
  per directory was written by a different on-disk encoding and is not
  readable: those entries decode to nothing and surface under their literal
  host names. Recreate the sysroot: unpack the rootfs again, with
  `--create-sysroot` if the volume folds case.
- Use `--create-sysroot PATH` if the host filesystem is case-insensitive
  (default APFS) and the sysroot is being provisioned for the first
  time; `elfuse` creates a case-sensitive APFS sparsebundle, mounts it
  at `PATH`, and uses it as the sysroot for this run.

## USB Devices

Linux USB tools see the Mac's attached devices. `/dev/bus/usb` and
`/sys/bus/usb/devices` are synthesized from the IOKit registry, and opening
a device node yields a usbfs-compatible fd driven over IOKit (see
[internals.md](internals.md), section "USB Device Passthrough").

What works unprivileged is what macOS itself leaves unclaimed: vendor-class
and bulk interfaces, which is the debug-probe and DFU population. `lsusb`,
libusb programs, and nusb-based tools such as the probe-rs family
enumerate, claim, and transfer against those directly, including async
URBs.

What does not: an interface bound to an Apple class driver (CDC serial,
HID, FTDI, mass storage) cannot be claimed, and `CLAIMINTERFACE` reports
`EBUSY` -- exactly what Linux reports for an interface a kernel driver
holds. For a CDC serial device, open the host's `/dev/cu.*` node from the
guest instead; the termios layer drives the real line.

A stock distribution `lsusb` does not run yet, and the reason is not the
USB layer. usbutils reaches libusb through libudev, whose monitor socket
wants `SO_ATTACH_FILTER`; elfuse's netlink layer answers that
`ENOPROTOOPT`, libudev's monitor never starts, and `libusb_init` gives up
with `-99`:

```console
$ build/elfuse --sysroot ./debian-sysroot /usr/bin/lsusb
unable to initialize libusb: -99
```

Programs that open the device nodes themselves, or that build libusb
without the udev backend, are unaffected.

## Debugging With GDB Or LLDB

`elfuse` includes a built-in GDB Remote Serial Protocol stub.

Start the guest and wait at entry:

```sh
build/elfuse --gdb 1234 --gdb-stop-on-entry ./guest-program
```

Attach with GNU GDB:

```sh
aarch64-linux-gnu-gdb -ex "target remote :1234" ./guest-program
```

Or attach with LLDB:

```sh
lldb --batch -o "gdb-remote 1234" ./guest-program
```

The stub supports all-stop debugging, up to 16 hardware breakpoints, up to 16
watchpoints, single-step (implemented as a temporary breakpoint), full register
and memory access, and per-thread inspection. Implementation details, including
the snapshot protocol used to keep Hypervisor.framework register access on the
owning thread, are documented in [internals.md](internals.md).

## Performance Analysis

`elfuse` can account for where a guest spends its time without an external
profiler. Set `ELFUSE_RUNTIME_STATS` to turn on a stats coordinator that
aggregates three sources at exit: shim fast-path counters, vCPU exit reasons,
and a per-syscall histogram (count, total, average, and max latency). All
output goes to stderr, so guest stdout stays clean for pipelines.

| `ELFUSE_RUNTIME_STATS` | Output |
|------------------------|--------|
| `summary` (the default for any nonempty value other than `json`, `jsonl`, or `0`) | Human-readable tables on exit |
| `json` | One JSON object per process on exit |
| `jsonl` | One JSON object per line: a final object plus one per on-demand snapshot |

Quick eyeball of a run:

```sh
ELFUSE_RUNTIME_STATS=summary build/elfuse ./guest-program 2>stats.txt
```

The summary prints a `vcpu-exit-stats` block (`exits_total`, `exits_vtimer`,
`exits_no_signal_cancel`, and `null_exit_share`) and a `syscall histogram`
sorted by total time, with a trailing line reporting what fraction of wall time
was spent inside syscalls. A high null-exit share or a syscall dominating total
time is the first thing to chase.

### On-Demand Snapshots

For a long-running guest, request a snapshot without stopping it by setting
`ELFUSE_STATS_SIGNAL=USR1` and sending `SIGUSR1` to the `elfuse` process:

```sh
ELFUSE_RUNTIME_STATS=jsonl ELFUSE_STATS_SIGNAL=USR1 \
    build/elfuse ./guest-program 2>stats.jsonl &
sleep 0.1        # let the process claim SIGUSR1
kill -USR1 $!    # emit a snapshot; repeat as the workload progresses
```

Each snapshot is one JSON line tagged `"reason":"signal","final":false`. The
final dump has `"final":true`; its `reason` is `"exit"` for the top-level
process and `"fork-child-exit"` for fork children, so filter on `"final"`
rather than the reason string. In `json` (not `jsonl`) mode, snapshots are
suppressed so each process writes a single JSON object. Each record goes out
in one `write`, which keeps records from a parent and its fork children whole
in a file; a pipe only guarantees that for writes up to 512 bytes, so send
stderr to a file when a forking guest is measured.

Snapshot requests are handled on elfuse's own signal thread and the record is
written by a separate stats thread, so it arrives even while the guest is
blocked in a long syscall, and no guest call sees an `EINTR` for it. The `sleep 0.1` matters only for a script that sends the signal
immediately: elfuse claims `SIGUSR1` early in startup, and one delivered before
then terminates the process by default. Without `ELFUSE_RUNTIME_STATS` or
`ELFUSE_SHIM_STATS`, `ELFUSE_STATS_SIGNAL` is ignored and `SIGUSR1` keeps its
default action.

### Timeline And Flamegraphs

`jsonl` mode plus `scripts/runtime-stats-convert.py` turns a run into viewer
formats. The `folded`, `speedscope`, and `perfetto` exports diff consecutive
snapshots per pid, so each interval shows the syscalls that ran during it; `csv`
emits the raw cumulative rows, one row per snapshot record:

```sh
# Flamegraph input (Brendan Gregg's flamegraph.pl):
scripts/runtime-stats-convert.py folded stats.jsonl | flamegraph.pl >stats.svg

# Load in https://www.speedscope.app:
scripts/runtime-stats-convert.py speedscope stats.jsonl >stats.speedscope.json

# Perfetto UI (https://ui.perfetto.dev):
scripts/runtime-stats-convert.py perfetto stats.jsonl >stats.perfetto.json

# Cumulative per-snapshot rows for a spreadsheet:
scripts/runtime-stats-convert.py csv stats.jsonl >stats.csv
```

The JSON schema (`elfuse-runtime-stats/1`) also carries a `phase` object of
coarse buckets summed from syscall-family totals: `clone_ns` (clone + clone3),
`wait_ns` (wait4 + waitid), `host_vfs_ns` (openat + openat2 only, also
reported as `path.open_ns`), `futex_ns`,
`mem_ns` (mmap + mprotect + madvise), and `process_lifecycle_ns` (clone + wait).
They are a quick read on where fork-heavy or lock-heavy guests spend time, not
independent phase timers; the raw histogram is authoritative.

### Startup Histogram

To profile just the dynamic-linker bring-up storm, use
`ELFUSE_STARTUP_TRACE=syscalls`, which freezes the histogram at the first
`execve` instead of recording the whole run. `ELFUSE_STARTUP_TRACE=syscalls-steady`
keeps recording past `execve` for steady-state workloads. Turning on
`ELFUSE_RUNTIME_STATS` implies steady-state recording.

Each fork child keeps its own counters from its first instruction and emits its
own final record, so per-process records add up rather than overlap. Within a
process the shim counters restart at each `execve`, because they live in the
shim's data page and a new image gets a fresh one; the syscall histogram and
vCPU exit counts cover the whole process. The same
holds for `syscalls-steady` without `ELFUSE_RUNTIME_STATS`: each child dumps its
own histogram at exit. Enabling stats adds a `clock_gettime` pair
plus atomic counter updates around each syscall; the disabled path is a
`pthread_once` guard and one atomic load, so leaving stats off costs
effectively nothing.

## Guest Compatibility Model

`elfuse` is designed for Linux user-space workloads, not for booting a Linux
kernel or presenting a complete Linux host environment. Compatibility comes
from targeted ABI translation and emulation at the syscall boundary.

That has a few direct implications:

- `/proc` and `/dev` are compatibility surfaces, not passthrough mounts.
- `uname` and `/proc/version` report Linux 6.18 LTS, a stable floor for
  version-gated feature detection; the implemented syscall set is
  `src/syscall/dispatch.tbl`. See [internals.md](internals.md), section
  "Reported Kernel Identity".
- macOS and Linux file, socket, and signal semantics are normalized in the host
  syscall layer.
- Behavior is strongest for normal command-line tools, language runtimes, test
  binaries, and debugger-driven workflows.
- Guest-internal FUSE means `/dev/fuse` and `mount(..., "fuse", ...)`
  work entirely inside the VM. Programs that link against `libfuse`
  (sshfs, ntfs-3g, AppImage runtimes) run without macFUSE, FUSE-T, or
  FSKit on the host.
- USB devices attached to the Mac are reachable: `/dev/bus/usb` and
  `/sys/bus/usb/devices` are built from the IOKit registry, and opening a
  device node gives a usbdevfs fd whose ioctls -- interface claim, control
  and bulk transfers, and asynchronous URBs -- drive the device through
  IOKit. macOS arbitrates per interface: a claim fails while a host driver
  holds that interface open. See
  [internals.md](internals.md), section "USB Device Passthrough", for the
  per-ioctl gaps.

## Diagnostic Environment Variables

Off by default, and useful when a guest misbehaves rather than in normal use:

- `ELFUSE_STARTUP_TRACE`: `steps` prints per-step VM bring-up timings,
  `syscalls` prints a per-syscall histogram of startup traffic (frozen at the
  first `execve`, so steady-state calls do not swamp it), `syscalls-steady`
  records the whole run instead, `all` does `steps` and `syscalls`.
  Comma-separated tokens are accepted, and `1` is a legacy alias for `steps`.
- `ELFUSE_SHIM_STATS=1`: dump the EL1 shim counter table and the vCPU exit
  counts to stderr at exit, one table per process, so a syscall that should be
  served inside the shim but takes the HVC #5 exit is attributed without a
  rebuild. It is the `summary` mode of `ELFUSE_RUNTIME_STATS` without the
  steady-state histogram.
- `ELFUSE_RUNTIME_STATS`, `ELFUSE_STATS_SIGNAL`: see
  [Performance Analysis](#performance-analysis).
- `ELFUSE_DISABLE_TLBI_RANGE=1`: refuse `FEAT_TLBIRANGE` and fall back to
  per-page and broadcast invalidation, which separates a stale-TLB bug from
  the range-encoding path.

## OCI Images

`scripts/elfuse-oci.py` runs OCI images under elfuse;
[oci-images.md](oci-images.md) describes the store, the sealed volumes, and the
per-run shadow. It needs crane and umoci (`brew install crane umoci`), and runs
`build/elfuse` from its checkout, else `elfuse` on `PATH`.

```sh
make elfuse
scripts/elfuse-oci.py run python:3.12-slim python3 -c 'print("hello")'
scripts/elfuse-oci.py clean
```

| Command | Effect |
|---------|--------|
| `pull REF` | Seal the `linux/arm64` image of `REF` unless the store holds it |
| `run [--entrypoint CMD] REF [ARG]...` | Run `REF` under elfuse, pulling it first when the store has no record of it |
| `clean` | Detach and remove every image, run, and interrupted pull in the store; refuse a non-empty directory that is not a store, and a store in use |
| `list` | Print each reference in the store with its image digest and size, and each unreferenced image as `<none>` |

`--entrypoint CMD` replaces the image Entrypoint and drops its Cmd; an empty
`CMD` leaves only the arguments. Every argument after `REF` goes to the guest.
The store is `$ELFUSE_OCI_STORE`, by default `~/.local/share/elfuse/oci`; a new
or empty directory becomes a store.

crane reads registry credentials from the Docker configuration
(`$DOCKER_CONFIG/config.json`, by default `~/.docker/config.json`) when one
exists, else from Podman's `$REGISTRY_AUTH_FILE` or
`$XDG_RUNTIME_DIR/containers/auth.json`.

### Running The Smoke Lane Locally

```sh
make elfuse
ELFUSE_OCI_STORE=/tmp/oci-scratch scripts/ci/oci-smoke.sh
```

The lane needs macOS with Hypervisor.framework and network access, and ends by
cleaning the store. Its coverage is in [oci-images.md](oci-images.md#validation).
