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
| `--sysroot PATH` | Resolve guest absolute paths under `PATH` first |
| `--create-sysroot PATH` | Provision a case-sensitive APFS sparsebundle mounted at `PATH`, then use it as the sysroot |
| `--no-rosetta` | Disable the x86_64-via-Rosetta translator (also `ELFUSE_NO_ROSETTA=1`) |
| `--gdb PORT` | Listen for a GDB RSP client on `PORT` (aarch64 guests only) |
| `--gdb-stop-on-entry` | Stop before the first guest instruction |
| `--` | End `elfuse` option parsing; remaining tokens are guest argv |

`--timeout` is a run-loop watchdog. It does not cap total process runtime. It
only bounds a single `hv_vcpu_run()` iteration before the host regains control,
which is what allows host-side timers and signals to be observed promptly.
Setting `--timeout 0` disables this watchdog for long-running CPU-bound guests.

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
no volume mount), so file arguments are just file arguments.

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
from the supplied sysroot, and redirects guest absolute-path opens to that tree
before falling back to the host filesystem.

Example:

```sh
build/elfuse --sysroot /path/to/sysroot ./hello-dynamic
```

This model supports both musl and glibc guest environments as long as the
expected interpreter path (for example `/lib/ld-musl-aarch64.so.1` or
`/lib/ld-linux-aarch64.so.1`) exists inside the sysroot.

Practical notes:

- The sysroot is consulted only for guest absolute paths; relative paths still
  resolve from the guest working directory.
- The sysroot setting is preserved across guest `fork` and `execve`, so spawned
  children see the same view of the filesystem.
- On case-insensitive macOS volumes, `elfuse` maintains per-directory
  sidecar token files so case-colliding Linux names remain distinct, and
  lookups verify the on-disk spelling byte-for-byte: a name that differs
  from an existing entry only by case (or Unicode normalization form)
  reports `ENOENT`, matching Linux semantics instead of APFS's folding.
- Use `--create-sysroot PATH` if the host filesystem is case-insensitive
  (default APFS) and the sysroot is being provisioned for the first
  time; `elfuse` creates a case-sensitive APFS sparsebundle, mounts it
  at `PATH`, and uses it as the sysroot for this run.

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
| `summary` (the default for any value other than `json`, `jsonl`, or `0`) | Human-readable tables on exit |
| `json` | Exactly one JSON object on exit |
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
sleep 0.1        # let the process install the SIGUSR1 handler
kill -USR1 $!    # emit a snapshot; repeat as the workload progresses
```

Each snapshot is one JSON line tagged `"reason":"signal","final":false`. The
final dump has `"final":true`; its `reason` is `"exit"` for the top-level
process, `"fork-child-exit"` (or `"fork-child-error"`) for fork children, so
filter on `"final"` rather than the reason string. In `json` (not `jsonl`)
mode, snapshots are suppressed so the output stays a single valid JSON document.

The `sleep 0.1` matters only for a script that sends the signal immediately: the
handler is installed early in startup, but `SIGUSR1` delivered before then
terminates the process by default.

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
`wait_ns` (wait4 + waitid), `host_vfs_ns` (openat + openat2 only), `futex_ns`,
`mem_ns` (mmap + mprotect + madvise), and `process_lifecycle_ns` (clone + wait).
They are a quick read on where fork-heavy or lock-heavy guests spend time, not
independent phase timers; the raw histogram is authoritative.

### Startup Histogram

To profile just the dynamic-linker bring-up storm, use
`ELFUSE_STARTUP_TRACE=syscalls`, which freezes the histogram at the first
`execve` instead of recording the whole run. `ELFUSE_STARTUP_TRACE=syscalls-steady`
keeps recording past `execve` for steady-state workloads. Turning on
`ELFUSE_RUNTIME_STATS` implies steady-state recording.

Counters reset per process, so fork children start from a clean window rather
than inheriting the parent's totals. Enabling stats adds a `clock_gettime` pair
plus atomic counter updates around each syscall; the disabled path is a
`pthread_once` guard and one atomic load, so leaving stats off costs
effectively nothing.

## Guest Compatibility Model

`elfuse` is designed for Linux user-space workloads, not for booting a Linux
kernel or presenting a complete Linux host environment. Compatibility comes
from targeted ABI translation and emulation at the syscall boundary.

That has a few direct implications:

- `/proc` and `/dev` are compatibility surfaces, not passthrough mounts.
- macOS and Linux file, socket, and signal semantics are normalized in the host
  syscall layer.
- Behavior is strongest for normal command-line tools, language runtimes, test
  binaries, and debugger-driven workflows.
- Guest-internal FUSE means `/dev/fuse` and `mount(..., "fuse", ...)`
  work entirely inside the VM. Programs that link against `libfuse`
  (sshfs, ntfs-3g, AppImage runtimes) run without macFUSE, FUSE-T, or
  FSKit on the host.
