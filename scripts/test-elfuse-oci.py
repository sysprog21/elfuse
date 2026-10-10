#!/usr/bin/env python3
"""Table tests for the parts of scripts/elfuse-oci.py that need no image.

Exit status is 1 when any case fails.
"""

import importlib.util
import json
import os
import shutil
import sys
import tempfile


def load_elfuse_oci():
    """Import scripts/elfuse-oci.py, whose name is not a Python identifier."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "elfuse-oci.py")
    spec = importlib.util.spec_from_file_location("elfuse_oci", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oci = load_elfuse_oci()


def main():
    """Run every case and return the exit status."""

    def find(cmd, path):
        on_path = {"/bin/hello", "/w/tools/hello", "/w/hello", "/w/bin/x"}.__contains__
        return oci.find_command(cmd, path, "/w", on_path)

    def attached(*paths):
        images = [
            {"image-path": p, "system-entities": [{"dev-entry": p}]} for p in paths
        ]
        return oci.store_devices({"images": images}, "/s")

    def half_attached(entities, image_path="/s/images/a.dmg"):
        images = [{"image-path": image_path, "system-entities": entities}]
        return oci.store_devices({"images": images}, "/s")

    tree = tempfile.mkdtemp()
    for d in ("r/etc", "r/usr/lib", "outside"):
        os.makedirs(os.path.join(tree, d))
    for link, target in (
        ("r/lib", "usr/lib"),
        ("r/abs", "/usr"),
        ("r/up", "../../../../../../../outside"),
        ("r/loop", "loop"),
        ("r/usr/lib/self", "."),
    ):
        os.symlink(target, os.path.join(tree, link))
    root = os.path.join(tree, "r")

    def resolve(path, follow_last=True):
        return os.path.relpath(oci.resolve_in_root(root, path, follow_last), tree)

    store = os.path.join(tree, "s")
    os.makedirs(os.path.join(store, "refs"))
    os.makedirs(os.path.join(store, "images"))
    for name, ref in (("h1", "b:1"), ("h2", "a:1")):
        with open(os.path.join(store, "refs", name), "w") as f:
            json.dump({"ref": ref, "digest": "sha256:aa"}, f)
    for name, size in (("aa.dmg", 3), ("bb.dmg", 5), (".DS_Store", 1)):
        with open(os.path.join(store, "images", name), "w") as f:
            f.write("x" * size)

    rootfs = os.path.join(tree, "f")
    os.makedirs(os.path.join(rootfs, "usr/lib/deep"))
    os.symlink("/usr", os.path.join(rootfs, "usr/lib/deep/abs"))
    os.symlink("/usr/lib", os.path.join(rootfs, "lib"))
    oci.fixup_rootfs(rootfs)

    cases = [
        (oci.relative_target, ("usr/bin/tool", "/bin/hello"), "../../bin/hello"),
        (oci.relative_target, ("a/b", "/usr/../../x"), "../x"),
        (oci.relative_target, ("a/b/c", "/"), "../../"),
        (oci.relative_target, ("top", "/"), "."),
        (resolve, ("/lib/x",), "r/usr/lib/x"),
        (resolve, ("/abs/lib",), "r/usr/lib"),
        (resolve, ("/up/x",), "r/outside/x"),
        (resolve, ("/usr/../etc",), "r/etc"),
        (resolve, ("/lib/self/self/x",), "r/usr/lib/x"),
        (resolve, ("/lib", False), "r/lib"),
        (resolve, ("/loop/x",), oci.Error),
        (oci.launch_argv, (["/ep"], ["c"], None, []), ["/ep", "c"]),
        (oci.launch_argv, (["/ep"], ["c"], None, ["a"]), ["/ep", "a"]),
        (oci.launch_argv, (["/ep"], ["c"], "/other", []), ["/other"]),
        (oci.launch_argv, (["/ep"], ["c"], "", ["sh"]), ["sh"]),
        (
            oci.merge_env,
            (["A=1", "NOEQ", "=x"],),
            {"A": "1", "PATH": oci.DEFAULT_PATH, "HOME": "/root"},
        ),
        (oci.merge_env, (["PATH=/p", "HOME=/h"],), {"PATH": "/p", "HOME": "/h"}),
        (oci.merge_env, (["PATH="],), {"PATH": oci.DEFAULT_PATH, "HOME": "/root"}),
        (find, ("hello", "/usr/bin:/bin"), "/bin/hello"),
        (find, ("bin/x", "/bin"), "/w/bin/x"),
        (find, ("/app/tool", "/bin"), oci.Error),
        (find, ("/bin/hello", "/x"), "/bin/hello"),
        (find, ("hello", "/usr/bin:tools"), "/w/tools/hello"),
        (find, ("hello", "/usr/bin::/bin"), "/w/hello"),
        (find, ("nosuch", "/bin"), oci.Error),
        (oci.parse_run_args, (["img", "a"],), (None, "img", ["a"])),
        (oci.parse_run_args, (["--entrypoint", "", "img"],), ("", "img", [])),
        (oci.parse_run_args, (["--entrypoint"],), oci.Error),
        (oci.parse_run_args, (["-e", "img"],), oci.Error),
        (
            attached,
            ("/s/images/a.dmg", "/s/tmp/9/v"),
            ["/s/images/a.dmg", "/s/tmp/9/v"],
        ),
        (attached, ("/s/cache.sparsebundle", "/s2/images/b.dmg", "/s/run/1/x"), []),
        (half_attached, ([],), oci.Error),
        (half_attached, ([{"content-hint": ""}],), oci.Error),
        (half_attached, ([], "/s2/images/b.dmg"), []),
        (
            oci.listing,
            (store,),
            [
                ("a:1", "sha256:aa", 3),
                ("b:1", "sha256:aa", 3),
                ("<none>", "sha256:bb", 5),
            ],
        ),
        (oci.listing, (os.path.join(tree, "outside"),), []),
        (os.readlink, (os.path.join(rootfs, "usr/lib/deep/abs"),), "../../../usr"),
        (os.readlink, (os.path.join(rootfs, "lib"),), "usr/lib"),
    ]
    failures = 0
    for fn, args, want in cases:
        try:
            got = fn(*args)
        except oci.Error:
            got = oci.Error
        if got != want:
            print(f"test-elfuse-oci: {fn.__name__}{args}: got {got!r}, want {want!r}")
            failures += 1
    shutil.rmtree(tree)
    if failures:
        return 1
    print(f"test-elfuse-oci: {len(cases)} cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
