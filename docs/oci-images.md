# OCI Images

An OCI image packages a filesystem as ordered, content-addressed layers plus a
JSON configuration; a manifest names both, and an image index selects a
manifest per platform. `scripts/elfuse-oci.py` pulls such an image, unpacks it
once into a volume of its own, and runs it under elfuse with that volume as the
sysroot. It adds no namespaces, cgroups, or other container isolation. Command
syntax is in [usage.md](usage.md#oci-images).

The script is Python 3.9 standard library code driving three tools: crane
fetches images, umoci unpacks them, and hdiutil creates and attaches the
volumes. `brew install crane umoci` provides the first two.

## Store

The store is `$ELFUSE_OCI_STORE`, by default `~/.local/share/elfuse/oci`:

```text
<store>/
  .elfuse-oci-store           marker and lock
  images/<manifest-hex>.dmg   one sealed volume per manifest digest
  refs/<sha256 of reference>  the reference and the digest it last resolved to
  run/<pid>/                  a running guest's mountpoint and shadow file
  tmp/<pid>/, tmp/<pid>.ref   a pull in progress
```

A directory becomes a store only while it is empty: `pull` and `run` write the
marker into a new or empty directory and refuse any other directory without
one, and `clean` refuses a non-empty directory without the marker. A mistyped
`ELFUSE_OCI_STORE` therefore never lets `clean` delete unrelated files. The
store is mode 0700 and each sealed image 0400, since an image may come from a
registry only its owner can read.

Every `pull` and `run` holds a shared `flock(2)` on the marker for its whole
life, a run through its watcher (below), and `clean` takes it exclusively. A
pull publishes into `images/` and `refs/` only by `link(2)` or `rename(2)` of a
complete file, so a pull or run that dies leaves its debris in its own
`tmp/<pid>/`, `tmp/<pid>.ref`, or `run/<pid>/`, where `clean` finds it. A later
process whose pid matches such a directory stops with an error rather than reuse
it.

## Pull

`pull` resolves the reference to its `linux/arm64` manifest digest with
`crane digest`. When `images/` already holds that digest, it only records the
reference. Otherwise it builds the image:

1. `crane pull --format oci` fetches the manifest by digest into a fresh OCI
   layout under `tmp/<pid>/`. Pulling by digest keeps a tag that moves after
   resolution from changing the content. The layout is never reused: crane
   appends to an existing `index.json`, and umoci refuses a reference that
   then resolves to two entries.
2. `hdiutil create` makes a case-sensitive APFS sparse image of 64 GiB
   capacity, allocated as written, and `umoci raw unpack --rootless` unpacks
   into it. A default macOS volume folds case, which a Linux rootfs does not
   expect.
3. The tree is adjusted, below, and the image configuration is copied beside
   the rootfs as `config.json`.
4. `hdiutil convert` writes the volume as an LZFSE-compressed read-only image
   (ULFO) and publishes it with `link(2)`, which never replaces an existing
   file, so of two concurrent pulls of one digest the first to publish wins.

The adjustments bring umoci's output to what a Linux unpack shows the guest:

- An absolute symlink target is rewritten relative to the link, as
  [filenames.md](filenames.md#symlink-targets) describes for guest links:
  anything following it natively would resolve it from the host root. `..` is
  clamped at the root, so the result cannot climb out of it.
- `/etc/hosts` and `/etc/resolv.conf` are removed. elfuse resolves them on the
  host when the sysroot lacks them, so the guest reads the host's live files,
  much as a container reads the files its runtime mounts over these paths.

A directory whose entries these adjustments change keeps its mode; a read-only
one is made writable only while it is edited.

Device nodes become empty regular files, since umoci cannot create them
without root. FIFOs and the set-id and sticky bits are kept as the image has
them. Names that differ only in Unicode normalization still
share one entry, because APFS is normalization-insensitive even when
case-sensitive.

## Run

`run` uses the digest `refs/` recorded, so a warm run needs no network; an
unknown reference is pulled first. It attaches the sealed image with a shadow
file under `run/<pid>/`: reads come from the image, writes go to the shadow
file, and the image itself is never written. A read-only sysroot alone is not
enough: elfuse resolves a guest's system directories, `/etc`, `/root`, `/run`,
and most of `/var` among them, and its `/tmp` only inside the sysroot
([filenames.md](filenames.md#the-sysroot-boundary-decides-whose-rules-apply)),
so guest writes there would fail. Each run starts from the same tree, and
concurrent runs of one image do not see each other's files.

Mounting writes about 23 MiB of APFS metadata into the shadow file at the
64 GiB capacity, which also bounds what one run can write.

The launch follows `docker run`:

- The command is the image Entrypoint followed by its Cmd. Arguments after
  the reference replace Cmd; `--entrypoint`, even an empty one, replaces
  Entrypoint and drops Cmd. A command without a slash is looked up in the
  final `PATH` inside the rootfs, and one with a slash but not absolute is
  taken relative to the working directory. Either way the command must be an
  executable file in the image: elfuse would fall back to a host file of the
  same path, so the script refuses to launch instead.
- The environment is the image Env, with a default `PATH` when it sets none or
  an empty one, and `HOME=/root` unless it sets `HOME`.
- The guest runs as `0:0`; the image User is ignored.
- The working directory is the image WorkingDir, else `/`, and is created if
  missing.

Whenever the script touches the tree itself, to create the working directory
or look up a command, it resolves the image's links inside the rootfs, so no
image link reaches a host file.

The script then execs `elfuse --sysroot <mount>/rootfs --user 0:0 --workdir DIR
--clear-env --env KEY=VALUE ... -- COMMAND`, so signals, the exit status,
and the terminal are elfuse's own. Before the exec it starts a watcher,
reparented to launchd so that elfuse never sees it as a child, which takes over
the store lock, waits for elfuse to exit through kqueue `NOTE_EXIT`, and then
detaches the volume and removes `run/<pid>/`. A run killed with SIGKILL is
cleaned up the same way. The watcher never detaches by force: while a guest
process that outlived elfuse still uses the volume, it waits.

## Clean

`clean` waits up to 10 seconds for the store's lock, which an exited run's
watcher releases once its volume is detached, and refuses a store still in use
by a pull or run. It then detaches every image attached from the store's
`images/` or `tmp/`, including the volumes of runs and pulls that were killed,
and removes `images/`, `refs/`, `run/`, and `tmp/`. It never detaches by force:
a volume a process still uses, or a directory that cannot be removed, fails the
command. Other files in the store directory are left alone.

## List

`list` prints a row per reference in `refs/`: the reference, the digest it last
resolved to, and the size of that sealed image. An image no reference resolves
to any more, left when a tag moved and was pulled again, shows as `<none>`.
`list` holds the store's lock shared while it reads and never creates a store.

## Validation

`scripts/test-elfuse-oci.py` runs table cases over the parts of
`scripts/elfuse-oci.py` that need no image. The self-hosted `oci-smoke` job runs
`scripts/ci/oci-smoke.sh`: those table tests, then pull, run, list, and clean
under elfuse on Alpine and Debian images, an image whose `/etc` climbs to a host
directory, and `clean` refusing a non-store and a store in use.
