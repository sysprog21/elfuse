# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import json
import os
import tempfile
import unittest
from pathlib import Path

from conformance import payload

SCHEMA = {"tool": {"commit": "hex40", "archive_sha256": "hex64", "url": "url", "epoch": "int"}}
GOOD = {"schema_version": 1, "tool": {"commit": "a" * 40, "archive_sha256": "b" * 64,
                                      "url": "https://x/y.tar.xz", "epoch": 7}}


class FingerprintTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.src = self.dir / "builder.py"
        self.src.write_text("v1")

    def tearDown(self):
        self.tmp.cleanup()

    def test_inputs_move_it(self):
        base = payload.fingerprint({"a": 1}, [self.src])
        self.assertEqual(base, payload.fingerprint({"a": 1}, [self.src]))
        self.assertNotEqual(base, payload.fingerprint({"a": 2}, [self.src]))
        self.assertNotEqual(base, payload.fingerprint({"a": 1}, [self.src], "docker"))
        os.utime(self.src, (1, 1))
        self.assertEqual(base, payload.fingerprint({"a": 1}, [self.src]))
        self.src.write_text("v2")
        self.assertNotEqual(base, payload.fingerprint({"a": 1}, [self.src]))


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "p"
        (self.root / "bin").mkdir(parents=True)
        (self.root / "bin" / "a").write_bytes(b"A")
        (self.root / "bin" / "a").chmod(0o755)
        os.symlink("bin", self.root / "lib64")

    def tearDown(self):
        self.tmp.cleanup()

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
        self.assertTrue(msg.startswith("conformance: gvisor payload missing ("))
        self.assertIn("run: make gvisor-payload", msg)


class PinsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "pins.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_shape(self):
        payload.check_pins(GOOD, SCHEMA)
        for field, value in (("commit", "A" * 40), ("archive_sha256", "b" * 63),
                             ("url", "http://x"), ("epoch", "7"), ("epoch", True)):
            doc = json.loads(json.dumps(GOOD))
            doc["tool"][field] = value
            with self.assertRaises(payload.PinError, msg=field):
                payload.check_pins(doc, SCHEMA)
        with self.assertRaises(payload.PinError):
            payload.check_pins({"schema_version": 1}, SCHEMA)

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


if __name__ == "__main__":
    unittest.main()
