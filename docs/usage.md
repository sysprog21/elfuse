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
or `--env` request is rejected before the VM is created, and `--workdir` is
resolved during bring-up, before the first guest instruction, so a bad request
fails with a diagnostic instead of launching a guest that runs as something
other than what was asked for.

`--user UID[:GID]` sets the identity the guest reports through `getuid` and
`getgid`. It does not change the host process credentials: elfuse translates the
guest's syscalls, so the number the guest sees is elfuse's to choose. The spec is
numeric, and a bare `UID` sets the group to the same value. Symbolic names are
resolved against the image `/etc/passwd` and `/etc/group` one layer up, by
`elfuse-oci`.

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
