#!/usr/bin/env python3
"""Pull, run, list, and clean OCI images under elfuse.

Each image is unpacked once into its own case-sensitive APFS volume, sealed
read-only, and attached per run with a shadow file that takes the run's
writes. crane downloads the image, umoci unpacks it, and hdiutil creates,
seals, and attaches the volumes.

The store is $ELFUSE_OCI_STORE (default ~/.local/share/elfuse/oci). It holds
the sealed images under images/, one record per pulled reference under refs/,
each run's mount point and shadow file under run/<pid>/, and each pull's work
under tmp/.
"""

import contextlib
import fcntl
import glob
import hashlib
import json
import os
import plistlib
import select
import shutil
import signal
import stat
import subprocess
import sys
import time

PLATFORM = "linux/arm64"
# A shadow mount writes about 23 MiB of APFS metadata at this capacity.
VOLUME_SIZE = "64g"
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
STORE_MARKER = ".elfuse-oci-store"
WATCHER_DETACH_SECONDS = 10
MAXSYMLINKS = 40
ATTACH = ["hdiutil", "attach", "-quiet", "-nobrowse", "-noverify"]
USAGE = """\
usage: elfuse-oci.py pull REF
       elfuse-oci.py run [--entrypoint CMD] REF [ARG...]
       elfuse-oci.py clean
       elfuse-oci.py list
The store is $ELFUSE_OCI_STORE (default ~/.local/share/elfuse/oci)."""


class Error(Exception):
    """A failure main reports as one line, without a traceback."""


def tool(*args, **kwargs):
    """Run a command, raising Error if it is missing or exits nonzero."""
    try:
        return subprocess.run(args, check=True, **kwargs)
    except FileNotFoundError:
        raise Error(f"{args[0]} not found (brew install crane umoci)") from None
    except subprocess.CalledProcessError as e:
        raise Error(f"{args[0]} {args[1]} exited {e.returncode}") from None


def output(*args):
    """Run a command and return its stdout as bytes."""
    return tool(*args, stdout=subprocess.PIPE).stdout


def detach(mnt):
    """Detach a volume only this process uses, by force if it must."""
    if not os.path.ismount(mnt):
        return
    for force in ([], ["-force"]):
        if subprocess.run(["hdiutil", "detach", "-quiet", *force, mnt]).returncode == 0:
            return


def relative_target(link_relpath, target):
    """Return an absolute symlink target rewritten relative to the link.

    link_relpath is the link's path inside the rootfs. Anything following an
    absolute link natively resolves it from the host root, so the target is
    stored relative to the link, as elfuse's symlinkat does (docs/filenames.md,
    "Symlink targets"). Like elfuse, .. is normalized away first and clamped at
    the root, so the result cannot climb out of it.
    """
    rel = os.path.normpath(target).lstrip("/")
    return "../" * link_relpath.count("/") + rel or "."


def resolve_in_root(root, guest_path, follow_last=True):
    """Return the host path of guest_path inside root.

    Links are followed as the guest would follow them: an absolute target
    restarts at root, and .. stops there. More than MAXSYMLINKS links raise
    Error.
    """
    parts = [p for p in guest_path.split("/") if p not in ("", ".")]
    resolved = []
    links = MAXSYMLINKS
    while parts:
        name = parts.pop(0)
        if name == "..":
            if resolved:
                resolved.pop()
            continue
        host = os.path.join(root, *resolved, name)
        if (parts or follow_last) and os.path.islink(host):
            links -= 1
            if links < 0:
                raise Error(f"too many links in {guest_path}")
            target = os.readlink(host)
            if target.startswith("/"):
                resolved = []
            parts = [p for p in target.split("/") if p not in ("", ".")] + parts
            continue
        resolved.append(name)
    return os.path.join(root, *resolved)


def launch_argv(entrypoint, cmd, override, args):
    """Return the guest argv from the image's Entrypoint and Cmd.

    Arguments given to run replace Cmd. Docker's rule: an --entrypoint
    override, even an empty one, replaces Entrypoint and drops Cmd.
    """
    if override is None:
        return entrypoint + (args or cmd)
    return ([override] if override else []) + args


def merge_env(image_env):
    """Return the image's Env as a dict, defaulting PATH and HOME.

    An entry without = or with an empty name is dropped. PATH falls back to
    DEFAULT_PATH when unset or empty, and HOME to /root when unset.
    """
    env = dict(entry.split("=", 1) for entry in image_env if entry.find("=") > 0)
    if not env.get("PATH"):
        env["PATH"] = DEFAULT_PATH
    env.setdefault("HOME", "/root")
    return env


def find_command(cmd, path, workdir, is_exec):
    """Return cmd as the absolute guest path elfuse takes for argv[0].

    elfuse resolves argv[0] before changing to the working directory, so a
    name with a slash is taken relative to workdir, and a bare name is looked
    up in path, the guest PATH, where an empty or relative entry is relative
    to workdir too. is_exec tests a candidate guest path. Raise Error when no
    candidate passes, since elfuse falls back to the host for a path the image
    lacks.
    """
    if "/" in cmd:
        dirs, missing = [""], "is not an executable file in the image"
    else:
        dirs, missing = path.split(":"), f"not found in PATH {path}"
    for d in dirs:
        candidate = os.path.join(workdir, d, cmd)
        if is_exec(candidate):
            return candidate
    raise Error(f"run: {cmd} {missing}")


def parse_run_args(argv):
    """Return (override, ref, guest_args) from run's arguments.

    override is the --entrypoint value, or None without the option.
    """
    override = None
    if argv[:1] == ["--entrypoint"]:
        if len(argv) == 1:
            raise Error("run: --entrypoint needs a value")
        override, argv = argv[1], argv[2:]
    if not argv:
        raise Error("run: missing image reference")
    if argv[0].startswith("-"):
        raise Error(f"run: unknown option {argv[0]}")
    ref, *guest_args = argv
    return override, ref, guest_args


def store_devices(hdiutil_info, store):
    """Return the devices of the images this store attached.

    hdiutil_info is parsed hdiutil info -plist output. The store attaches its
    sealed images from images/ and its build volumes from tmp/. hdiutil lists
    an image without its device while it is attaching or detaching it, so
    such an image raises Error rather than passing for detached.
    """
    prefixes = (os.path.join(store, "images", ""), os.path.join(store, "tmp", ""))
    devices = []
    for image in hdiutil_info.get("images", []):
        image_path = image.get("image-path", "")
        if image_path.startswith(prefixes):
            dev = (image.get("system-entities") or [{}])[0].get("dev-entry")
            if dev is None:
                raise Error(f"{image_path} is still attaching or detaching")
            devices.append(dev)
    return devices


def read_hdiutil_info():
    """Return the parsed output of hdiutil info -plist."""
    return plistlib.loads(output("hdiutil", "info", "-plist"))


def store_root():
    """Return $ELFUSE_OCI_STORE, or the default store path, unresolved."""
    default = os.path.expanduser("~/.local/share/elfuse/oci")
    return os.environ.get("ELFUSE_OCI_STORE") or default


def open_store():
    """Return the store's resolved path, making the store if needed.

    The path is resolved so it matches the image paths hdiutil reports. A
    directory becomes a store only while it is empty, and clean refuses a
    non-empty one without the marker, so a mistyped ELFUSE_OCI_STORE cannot
    point clean at unrelated files. The store is private to its owner, since
    an image may come from a registry only its owner can read.
    """
    os.makedirs(store_root(), exist_ok=True)
    store = os.path.realpath(store_root())
    marker = os.path.join(store, STORE_MARKER)
    if not os.path.isfile(marker):
        if set(os.listdir(store)) - {STORE_MARKER}:
            raise Error(f"{store} is not empty and not an elfuse-oci store")
        os.chmod(store, 0o700)
        open(marker, "w").close()
    return store


def share_store(store):
    """Take the store's lock shared and return its descriptor.

    The lock is held for the life of this process and its forks; clean takes
    it exclusively.
    """
    lock = os.open(os.path.join(store, STORE_MARKER), os.O_RDONLY)
    fcntl.flock(lock, fcntl.LOCK_SH)
    return lock


def fresh_dir(path, command):
    """Create path under a per-pid directory that must not exist yet.

    One that exists was left by a killed command whose pid this process
    reuses, and only clean removes it.
    """
    pid_dir = os.path.dirname(path)
    if os.path.lexists(pid_dir):
        raise Error(f"{pid_dir} is left from a killed {command}; clean removes it")
    os.makedirs(path)


def image_path(store, digest):
    """Return the path of the sealed image for a manifest digest."""
    return os.path.join(store, "images", digest.split(":", 1)[1] + ".dmg")


def ref_path(store, ref):
    """Return the path of ref's record, named by the SHA-256 of ref."""
    return os.path.join(store, "refs", hashlib.sha256(ref.encode()).hexdigest())


def blob(layout, digest):
    """Return the path of a blob in an OCI image layout."""
    return os.path.join(layout, "blobs", *digest.split(":", 1))


def load_json(path):
    """Return the parsed contents of a JSON file."""
    with open(path) as f:
        return json.load(f)


def fixup_rootfs(root):
    """Bring a umoci tree to what a Linux unpack shows the guest.

    Absolute symlink targets are rewritten relative to the link. /etc/hosts
    and /etc/resolv.conf are removed, since Docker mounts its own over them,
    and without them elfuse falls back to the host's.
    """
    original_modes = {}

    def make_parent_writable(path):
        parent = os.path.dirname(path)
        if parent not in original_modes:
            original_modes[parent] = stat.S_IMODE(os.stat(parent).st_mode)
            os.chmod(parent, original_modes[parent] | stat.S_IWUSR)

    dirs = [root]
    while dirs:
        for entry in list(os.scandir(dirs.pop())):
            if entry.is_dir(follow_symlinks=False):
                dirs.append(entry.path)
            elif entry.is_symlink():
                target = os.readlink(entry.path)
                if target.startswith("/"):
                    make_parent_writable(entry.path)
                    os.unlink(entry.path)
                    link_relpath = os.path.relpath(entry.path, root)
                    os.symlink(relative_target(link_relpath, target), entry.path)
    for name in ("hosts", "resolv.conf"):
        path = resolve_in_root(root, f"/etc/{name}", follow_last=False)
        if os.path.lexists(path) and not stat.S_ISDIR(os.lstat(path).st_mode):
            make_parent_writable(path)
            os.unlink(path)
    for parent, mode in original_modes.items():
        os.chmod(parent, mode)


def build(store, ref, digest):
    """Unpack ref at digest into a fresh volume and publish it sealed."""
    tmp = os.path.join(store, "tmp", str(os.getpid()))
    mnt = os.path.join(tmp, "mnt")
    layout = os.path.join(tmp, "layout")
    volume = os.path.join(tmp, "vol.sparseimage")
    sealed = os.path.join(tmp, "sealed.dmg")
    fresh_dir(mnt, "pull")
    os.makedirs(os.path.join(store, "images"), exist_ok=True)
    try:
        print(f"Downloading {ref} -> {digest}", file=sys.stderr)
        # A fresh layout per pull keeps index.json to the one entry umoci
        # resolves; crane appends to an existing one.
        flags = ["--platform", PLATFORM, "--format", "oci", "--annotate-ref"]
        source = f"{ref.split('@', 1)[0]}@{digest}"
        tool("crane", "pull", *flags, source, layout, stdout=sys.stderr)
        desc = load_json(os.path.join(layout, "index.json"))["manifests"][0]
        name = desc["annotations"]["org.opencontainers.image.ref.name"]
        config = load_json(blob(layout, desc["digest"]))["config"]["digest"]

        print(f"Unpacking {ref} -> {digest}", file=sys.stderr)
        fs = ["-fs", "Case-sensitive APFS", "-type", "SPARSE", "-size", VOLUME_SIZE]
        tool("hdiutil", "create", "-quiet", *fs, "-volname", "elfuse-oci", volume)
        tool(*ATTACH, "-mountpoint", mnt, volume)
        os.mkdir(os.path.join(mnt, ".fseventsd"))
        for marker in (".metadata_never_index", ".fseventsd/no_log"):
            open(os.path.join(mnt, marker), "w").close()
        shutil.copyfile(blob(layout, config), os.path.join(mnt, "config.json"))

        rootfs = os.path.join(mnt, "rootfs")
        image = f"{layout}:{name}"
        try:
            unpack = subprocess.run(
                ["umoci", "raw", "unpack", "--rootless", "--image", image, rootfs],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except FileNotFoundError:
            raise Error("umoci not found (brew install crane umoci)") from None
        if unpack.returncode:
            sys.stderr.write(unpack.stdout)
            raise Error(f"unpack {ref} failed")
        fixup_rootfs(rootfs)
        print(f"Sealing {ref} -> {digest}", file=sys.stderr)
        detach(mnt)

        tool("hdiutil", "convert", "-quiet", "-format", "ULFO", "-o", sealed, volume)
        os.chmod(sealed, 0o400)
        # link(2) never replaces: a concurrent build that published the same
        # digest first wins, and this copy is dropped with tmp.
        with contextlib.suppress(FileExistsError):
            os.link(sealed, image_path(store, digest))
    finally:
        detach(mnt)
        if not os.path.ismount(mnt):
            shutil.rmtree(tmp, ignore_errors=True)


def pull(store, ref):
    """Resolve ref, build its image unless already sealed, and record it.

    Return the manifest digest ref resolved to.
    """
    print(f"Resolving {ref}", file=sys.stderr)
    digest = output("crane", "digest", "--platform", PLATFORM, ref).decode().strip()
    if not os.path.exists(image_path(store, digest)):
        build(store, ref, digest)
    path = ref_path(store, ref)
    tmp = os.path.join(store, "tmp", f"{os.getpid()}.ref")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    os.makedirs(os.path.dirname(tmp), exist_ok=True)
    with open(tmp, "w") as f:
        json.dump({"ref": ref, "digest": digest}, f)
    os.rename(tmp, path)
    return digest


def start_watcher(pid, mnt, run_dir, lock):
    """Detach the run's volume once pid, about to become elfuse, exits.

    The watcher is reparented to launchd so a guest wait() inside elfuse never
    sees it, waits on NOTE_EXIT so a SIGKILLed elfuse is cleaned up too, and
    holds no inherited descriptor but the store lock, so a caller reading the
    run's output is not kept waiting on it.
    """
    child = os.fork()
    if child:
        os.waitpid(child, 0)
        return
    try:
        if os.fork():
            os._exit(0)
        os.setsid()
        os.chdir("/")
        for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)
        null = os.open(os.devnull, os.O_RDWR)
        for fd in range(3):
            os.dup2(null, fd)
        for fd in map(int, os.listdir("/dev/fd")):
            if fd > 2 and fd != lock:
                with contextlib.suppress(OSError):
                    os.close(fd)
        exit_event = select.kevent(
            pid,
            filter=select.KQ_FILTER_PROC,
            flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
            fflags=select.KQ_NOTE_EXIT,
        )
        # A pid that already exited returns an EV_ERROR event instead of raising.
        select.kqueue().control([exit_event], 1, None)
        # A guest process that outlived elfuse keeps the volume busy, so it
        # stays attached, and the store locked, until that process exits.
        detach_cmd = ["hdiutil", "detach", "-quiet", mnt]
        while os.path.ismount(mnt) and subprocess.run(detach_cmd).returncode:
            time.sleep(1)
        shutil.rmtree(run_dir, ignore_errors=True)
    finally:
        os._exit(0)


def find_elfuse():
    """Return this checkout's build/elfuse if executable, else elfuse on PATH."""
    root = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    built = os.path.join(root, "build", "elfuse")
    found = built if os.access(built, os.X_OK) else shutil.which("elfuse")
    if not found:
        raise Error("elfuse not found; run make elfuse")
    return found


def cmd_run(argv):
    """Run an image's command under elfuse, pulling the image if needed.

    argv holds run's arguments. On success this process execs elfuse and
    does not return.
    """
    override, ref, args = parse_run_args(argv)
    elfuse = find_elfuse()
    store = open_store()
    lock = share_store(store)
    digest = ""
    with contextlib.suppress(FileNotFoundError):
        digest = load_json(ref_path(store, ref))["digest"]
    if not digest or not os.path.exists(image_path(store, digest)):
        digest = pull(store, ref)

    run_dir = os.path.join(store, "run", str(os.getpid()))
    root = os.path.join(run_dir, "root")
    rootfs = os.path.join(root, "rootfs")
    fresh_dir(root, "run")
    try:
        shadow = ["-noautofsck", "-shadow", os.path.join(run_dir, "shadow")]
        tool(*ATTACH, *shadow, "-mountpoint", root, image_path(store, digest))
        config = load_json(os.path.join(root, "config.json")).get("config") or {}
        entrypoint = config.get("Entrypoint") or []
        guest_argv = launch_argv(entrypoint, config.get("Cmd") or [], override, args)
        if not guest_argv:
            raise Error(f"run: {ref} has no command; pass one")
        env = merge_env(config.get("Env") or [])
        workdir = config.get("WorkingDir") or "/"
        # Every host-side access below resolves the image's links inside the
        # rootfs, so none can reach host files.
        os.makedirs(resolve_in_root(rootfs, workdir), exist_ok=True)

        def is_exec(p):
            host = resolve_in_root(rootfs, p)
            return os.path.isfile(host) and os.access(host, os.X_OK)

        guest_argv[0] = find_command(guest_argv[0], env["PATH"], workdir, is_exec)
        start_watcher(os.getpid(), root, run_dir, lock)
    except BaseException:
        detach(root)
        if not os.path.ismount(root):
            shutil.rmtree(run_dir, ignore_errors=True)
        raise
    command = [elfuse, "--sysroot", rootfs, "--user", "0:0"]
    command += ["--workdir", workdir, "--clear-env"]
    for key, value in env.items():
        command += ["--env", f"{key}={value}"]
    try:
        os.execv(elfuse, command + ["--"] + guest_argv)
    except OSError as e:
        raise Error(f"cannot run {elfuse}: {e.strerror}") from None


def cmd_clean():
    """Detach the images this store attached and remove everything it holds.

    That includes what killed pulls and runs left behind. A non-empty
    directory without the marker is refused, and so is a store a pull or run
    still holds after WATCHER_DETACH_SECONDS.
    """
    if not os.path.isdir(store_root()) or not os.listdir(store_root()):
        print(f"Nothing to clean at {store_root()}")
        return
    store = os.path.realpath(store_root())
    if not os.path.isfile(os.path.join(store, STORE_MARKER)):
        raise Error(f"{store} is not an elfuse-oci store; not cleaning it")
    lock = os.open(os.path.join(store, STORE_MARKER), os.O_RDONLY)
    for _ in range(WATCHER_DETACH_SECONDS * 5):
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            time.sleep(0.2)
    else:
        raise Error(f"{store} is in use by a pull or run")
    # Nothing is detached with -force: a volume a process still uses stays.
    for dev in store_devices(read_hdiutil_info(), store):
        subprocess.run(["hdiutil", "detach", "-quiet", dev], stderr=subprocess.DEVNULL)
    still_attached = store_devices(read_hdiutil_info(), store)
    if still_attached:
        raise Error(f"cannot detach {' '.join(still_attached)}; still in use")
    for name in ("images", "refs", "run", "tmp"):
        path = os.path.join(store, name)
        shutil.rmtree(path, ignore_errors=True)
        if os.path.lexists(path):
            raise Error(f"cannot remove {path}")
    print(f"Removed images and runs under {store}")


def listing(store):
    """Return (reference, digest, size) rows for the store's sealed images.

    One row per reference whose record names a sealed image, sorted, then one
    <none> row per image no record names.
    """
    refs_by_digest = {}
    for path in glob.glob(os.path.join(store, "refs", "*")):
        record = load_json(path)
        refs_by_digest.setdefault(record["digest"], []).append(record["ref"])
    rows = []
    for path in glob.glob(os.path.join(store, "images", "*.dmg")):
        digest = "sha256:" + os.path.basename(path).removesuffix(".dmg")
        size = os.path.getsize(path)
        refs = refs_by_digest.get(digest, ["<none>"])
        rows += [(ref, digest, size) for ref in refs]
    return sorted(rows, key=lambda row: (row[0] == "<none>", row))


def cmd_list():
    """Print the store's images as a table.

    A directory without the marker holds none, and list never creates a store.
    """
    store = store_root()
    rows = []
    if os.path.isfile(os.path.join(store, STORE_MARKER)):
        share_store(store)
        rows = listing(store)
    table = [("REFERENCE", "DIGEST", "SIZE")]
    table += [(ref, digest, f"{size / 2**20:.1f} MiB") for ref, digest, size in rows]
    widths = [max(map(len, column)) for column in zip(*table)]
    for row in table:
        print("  ".join(f"{cell:{width}}" for cell, width in zip(row, widths)).rstrip())


def main(argv):
    """Dispatch the command in argv and return the exit status."""
    command = argv[0] if argv else ""
    try:
        if command == "pull" and len(argv) == 2:
            store = open_store()
            share_store(store)
            print(f"Pulled {argv[1]} -> {pull(store, argv[1])}", file=sys.stderr)
        elif command == "run":
            cmd_run(argv[1:])
        elif command == "clean" and len(argv) == 1:
            cmd_clean()
        elif command == "list" and len(argv) == 1:
            cmd_list()
        else:
            print(USAGE, file=sys.stderr)
            return 2
    except Error as e:
        print(f"elfuse-oci: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
