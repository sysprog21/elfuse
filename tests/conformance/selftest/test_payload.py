# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import json
import os
import unittest
from pathlib import Path

from conformance import EXIT_DRIFT, EXIT_OK, EXIT_USAGE, payload
from conformance.selftest.fixture import TempDirTest

SCHEMA = {"tool": {"commit": "hex40", "archive_sha256": "hex64", "url": "url", "epoch": "int",
                   "name": "str"}}
GOOD = {"schema_version": 1, "tool": {"commit": "a" * 40, "archive_sha256": "b" * 64,
                                      "url": "https://x/y.tar.xz", "epoch": 7, "name": "t"}}


class FingerprintTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.src = self.dir / "builder.py"
        self.src.write_text("v1")

    def test_inputs_move_it(self):
        base = payload.fingerprint({"a": 1}, [self.src])
        self.assertEqual(base, payload.fingerprint({"a": 1}, [self.src]))
        self.assertNotEqual(base, payload.fingerprint({"a": 2}, [self.src]))
        self.assertNotEqual(base, payload.fingerprint({"a": 1}, [self.src], "docker"))
        os.utime(self.src, (1, 1))
        self.assertEqual(base, payload.fingerprint({"a": 1}, [self.src]))
        self.src.write_text("v2")
        self.assertNotEqual(base, payload.fingerprint({"a": 1}, [self.src]))


class ManifestTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.root = self.dir / "p"
        (self.root / "bin").mkdir(parents=True)
        (self.root / "bin" / "a").write_bytes(b"A")
        (self.root / "bin" / "a").chmod(0o755)
        os.symlink("bin", self.root / "lib64")

    def test_round_trip(self):
        doc = payload.write_manifest(self.root, "f" * 64, {"binaries": 1})
        self.assertEqual(doc["files"]["bin/a"]["mode"], "755")
        self.assertEqual(doc["files"]["lib64"], {"link": "bin"})
        self.assertNotIn(payload.MANIFEST, doc["files"])
        self.assertEqual(payload.verify(self.root, "f" * 64)["extra"], {"binaries": 1})
        self.assertEqual(payload.status(self.root, "f" * 64), "ok")
        self.assertEqual(payload.status(self.root, "0" * 64), "stale")

    def test_missing_stale_corrupt(self):
        with self.assertRaises(payload.PayloadError) as cm:
            payload.verify(self.root)
        self.assertEqual(cm.exception.kind, "missing")
        self.assertEqual(payload.status(self.root, "x"), "missing")
        payload.write_manifest(self.root, "f" * 64)
        with self.assertRaises(payload.PayloadError) as cm:
            payload.verify(self.root, "0" * 64)
        self.assertEqual(cm.exception.kind, "stale")
        (self.root / "bin" / "a").write_bytes(b"B")
        (self.root / "bin" / "extra").write_bytes(b"")
        with self.assertRaises(payload.PayloadError) as cm:
            payload.verify(self.root, "f" * 64)
        self.assertEqual(cm.exception.kind, "corrupt")
        self.assertIn("changed: bin/a", str(cm.exception))
        self.assertIn("extra: bin/extra", str(cm.exception))

    def test_a_wrong_manifest_shape_is_corrupt(self):
        good = payload.write_manifest(self.root, "f" * 64)
        (self.root / payload.MANIFEST).write_text(json.dumps({k: v for k, v in good.items() if k != "volatile"}))
        payload.verify(self.root, "f" * 64)
        for field, value in (("files", ["bin/a"]), ("volatile", "tmp"), ("volatile", [7])):
            doc = dict(good, **{field: value})
            (self.root / payload.MANIFEST).write_text(json.dumps(doc))
            with self.assertRaises(payload.PayloadError, msg=field) as cm:
                payload.verify(self.root, "f" * 64)
            self.assertEqual(cm.exception.kind, "corrupt")
            self.assertIn("unexpected shape", str(cm.exception))

    def test_volatile_prefixes(self):
        payload.write_manifest(self.root, "f" * 64, volatile=["bin/scratch/"])
        (self.root / "bin" / "scratch").mkdir()
        (self.root / "bin" / "scratch" / "left-by-a-guest").write_bytes(b"x")
        payload.verify(self.root, "f" * 64)
        (self.root / "bin" / "stray").write_bytes(b"x")
        with self.assertRaises(payload.PayloadError):
            payload.verify(self.root, "f" * 64)

    def test_volatile_bounds_at_a_path_segment(self):
        payload.write_manifest(self.root, "f" * 64, volatile=["bin/scratch"])
        (self.root / "bin" / "scratch").mkdir()
        (self.root / "bin" / "scratch" / "left-by-a-guest").write_bytes(b"x")
        payload.verify(self.root, "f" * 64)
        (self.root / "bin" / "scratchpad").mkdir()
        (self.root / "bin" / "scratchpad" / "sneaky").write_bytes(b"x")
        with self.assertRaises(payload.PayloadError) as cm:
            payload.verify(self.root, "f" * 64)
        self.assertIn("bin/scratchpad/sneaky", str(cm.exception))

    def test_message(self):
        msg = payload.absent_message("gvisor", self.root, "missing", "make gvisor-payload")
        self.assertTrue(msg.startswith("gvisor payload missing ("))
        self.assertIn("run: make gvisor-payload", msg)


class PinsTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.path = self.dir / "pins.json"

    def test_shape(self):
        payload.check_pins(GOOD, SCHEMA)
        for field, value in (("commit", "A" * 40), ("archive_sha256", "b" * 63),
                             ("url", "http://x"), ("epoch", "7"), ("epoch", True), ("name", "")):
            doc = json.loads(json.dumps(GOOD))
            doc["tool"][field] = value
            with self.assertRaises(payload.PinError, msg=field):
                payload.check_pins(doc, SCHEMA)
        with self.assertRaises(payload.PinError):
            payload.check_pins({"schema_version": 1}, SCHEMA)
        with self.assertRaises(payload.PinError):
            payload.check_pins(GOOD, {"tool": {"commit": "sha1"}})

    def test_write_is_validated_and_atomic(self):
        payload.write_pins(self.path, GOOD, SCHEMA)
        before = self.path.read_text()
        bad = json.loads(before)
        bad["tool"]["commit"] = "nope"
        with self.assertRaises(payload.PinError):
            payload.write_pins(self.path, bad, SCHEMA)
        self.assertEqual(self.path.read_text(), before)
        self.assertEqual(payload.load_pins(self.path, SCHEMA), GOOD)
        self.assertEqual([p.name for p in self.path.parent.iterdir()], ["pins.json"])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o644)


PIN_SCHEMA = {"tool": {"commit": "hex40"}}


class Stub:
    name = "tool"

    def __init__(self, path, commit, fail=False, error=None):
        self.pins_path, self.pins_schema = path, PIN_SCHEMA
        self.commit, self.fail, self.refs = commit, fail, []
        self.error = error

    def latest_pin(self, doc, ref):
        self.refs.append(ref)
        if self.error is not None:
            raise self.error
        if self.fail:
            raise payload.UpdateError("api unreachable")
        doc["tool"]["commit"] = self.commit
        return doc

    def update_next_steps(self):
        return ["make tool-payload"]


class RefreshTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.path = self.dir / "pins.json"
        payload.write_pins(self.path, {"schema_version": 1, "tool": {"commit": "a" * 40}}, PIN_SCHEMA)
        self.before = self.path.read_text()
        self.lines = []
        self.errors = []

    def test_current_is_untouched(self):
        rc = payload.refresh(Stub(self.path, "a" * 40), out=self.lines.append)
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(self.path.read_text(), self.before)
        self.assertIn("pins are current", self.lines[-1])

    def test_check_reports_drift_without_writing(self):
        stub = Stub(self.path, "b" * 40)
        rc = payload.refresh(stub, ref="v2", check=True, out=self.lines.append)
        self.assertEqual(rc, EXIT_DRIFT)
        self.assertEqual(self.path.read_text(), self.before)
        self.assertEqual(stub.refs, ["v2"])
        self.assertIn("tool.commit: %r -> %r" % ("a" * 40, "b" * 40), self.lines[0])
        self.assertIn("scripts/conformance pins update tool", self.lines[-1])

    def test_write(self):
        rc = payload.refresh(Stub(self.path, "b" * 40), out=self.lines.append)
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(json.loads(self.path.read_text())["tool"]["commit"], "b" * 40)
        self.assertIn("next: make tool-payload", self.lines[-1])

    def test_invalid_never_replaces(self):
        rc = payload.refresh(Stub(self.path, "not a digest"), fail=self.errors.append)
        self.assertEqual(rc, EXIT_USAGE)
        self.assertEqual(self.path.read_text(), self.before)

    def test_upstream_error(self):
        rc = payload.refresh(Stub(self.path, "b" * 40, fail=True), fail=self.errors.append)
        self.assertEqual(rc, EXIT_USAGE)
        self.assertIn("api unreachable", self.errors[0])

    def test_diff_sections(self):
        self.assertEqual(payload.diff_pins({"a": {"x": 1}}, {"a": {"x": 1}, "b": {"y": 2}}),
                         ["b: None -> {'y': 2}"])
        self.assertEqual(payload.diff_pins({"a": {"x": 1, "y": 1}}, {"a": {"x": 2, "y": 1}}),
                         ["a.x: 1 -> 2"])

    def test_a_bad_upstream_is_an_error_not_a_traceback(self):
        for error in (OSError("unreachable"), KeyError("tag_name"), IndexError("x")):
            out = []
            rc = payload.refresh(Stub(self.path, "b" * 40, error=error),
                                 None, False, out.append, out.append)
            self.assertEqual(rc, EXIT_USAGE, error)
            self.assertEqual(self.path.read_text(), self.before)

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_an_unwritable_pins_directory_is_an_error(self):
        os.chmod(self.dir, 0o500)
        try:
            rc = payload.refresh(Stub(self.path, "b" * 40), out=self.lines.append,
                                 fail=self.errors.append)
        finally:
            os.chmod(self.dir, 0o700)
        self.assertEqual(rc, EXIT_USAGE)
        self.assertTrue(self.errors)
        self.assertEqual(self.path.read_text(), self.before)


if __name__ == "__main__":
    unittest.main()
