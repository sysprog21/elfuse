# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import json
import os
import tempfile
import unittest
from pathlib import Path

from conformance import payload, update

SCHEMA = {"tool": {"commit": "hex40"}}


class Stub:
    def __init__(self, path, commit, fail=False, error=None):
        self.pins_path, self.pins_schema = path, SCHEMA
        self.commit, self.fail, self.refs = commit, fail, []
        self.error = error

    def latest_pin(self, doc, ref):
        self.refs.append(ref)
        if self.error is not None:
            raise self.error
        if self.fail:
            raise update.UpdateError("api unreachable")
        doc["tool"]["commit"] = self.commit
        return doc

    def update_next_steps(self):
        return ["make tool-payload"]


class UpdateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "pins.json"
        payload.write_pins(self.path, {"schema_version": 1, "tool": {"commit": "a" * 40}}, SCHEMA)
        self.before = self.path.read_text()
        self.lines = []

    def tearDown(self):
        self.tmp.cleanup()

    def test_current_is_untouched(self):
        rc = update.refresh(Stub(self.path, "a" * 40), out=self.lines.append)
        self.assertEqual(rc, update.EXIT_CURRENT)
        self.assertEqual(self.path.read_text(), self.before)
        self.assertIn("pins are current", self.lines[-1])

    def test_check_reports_drift_without_writing(self):
        stub = Stub(self.path, "b" * 40)
        rc = update.refresh(stub, ref="v2", check=True, out=self.lines.append)
        self.assertEqual(rc, update.EXIT_DRIFT)
        self.assertEqual(self.path.read_text(), self.before)
        self.assertEqual(stub.refs, ["v2"])
        self.assertIn("tool.commit: %r -> %r" % ("a" * 40, "b" * 40), self.lines[0])

    def test_write(self):
        rc = update.refresh(Stub(self.path, "b" * 40), out=self.lines.append)
        self.assertEqual(rc, update.EXIT_CURRENT)
        self.assertEqual(json.loads(self.path.read_text())["tool"]["commit"], "b" * 40)
        self.assertIn("next: make tool-payload", self.lines[-1])

    def test_invalid_never_replaces(self):
        rc = update.refresh(Stub(self.path, "not a digest"), out=self.lines.append)
        self.assertEqual(rc, update.EXIT_ERROR)
        self.assertEqual(self.path.read_text(), self.before)

    def test_upstream_error(self):
        rc = update.refresh(Stub(self.path, "b" * 40, fail=True), out=self.lines.append)
        self.assertEqual(rc, update.EXIT_ERROR)
        self.assertIn("api unreachable", self.lines[0])

    def test_diff_sections(self):
        self.assertEqual(update.diff({"a": {"x": 1}}, {"a": {"x": 1}, "b": {"y": 2}}),
                         ["b: None -> {'y': 2}"])
        self.assertEqual(update.diff({"a": {"x": 1, "y": 1}}, {"a": {"x": 2, "y": 1}}),
                         ["a.x: 1 -> 2"])

    def test_a_network_failure_is_an_error_not_a_traceback(self):
        out = []
        rc = update.refresh(Stub(self.path, "b" * 40, error=OSError("unreachable")),
                            None, False, out.append)
        self.assertEqual(rc, update.EXIT_ERROR)
        self.assertIn("unreachable", out[0])
        self.assertEqual(self.path.read_text(), self.before)

    def test_an_unwritable_pins_directory_is_an_error(self):
        os.chmod(self.tmp.name, 0o500)
        try:
            rc = update.refresh(Stub(self.path, "b" * 40), out=self.lines.append)
        finally:
            os.chmod(self.tmp.name, 0o700)
        self.assertEqual(rc, update.EXIT_ERROR)
        self.assertTrue(self.lines[-1].startswith("conformance: "))
        self.assertEqual(self.path.read_text(), self.before)


if __name__ == "__main__":
    unittest.main()
