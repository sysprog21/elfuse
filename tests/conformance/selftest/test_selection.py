# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import unittest
from pathlib import Path

from conformance import selection

DATA = Path(__file__).resolve().parents[1] / "data" / "fake.jsonc"


class SelectionTest(unittest.TestCase):
    def test_shipped_file(self):
        sel = selection.load(DATA)
        self.assertEqual([e.group for e in sel.groups("pr")], ["basic"])
        self.assertEqual([e.group for e in sel.groups("full")], ["basic", "slow", "narrow", "recorded"])
        self.assertEqual(sel.entry("slow").timeout_s, 1)
        self.assertEqual(sel.entry("narrow").only, ("keep*",))
        self.assertEqual(sel.declined, [("needs a kernel facility the host does not have", ("kernel",))])

    def test_full_is_a_superset(self):
        sel = selection.load(DATA)
        pr = {e.group for e in sel.groups("pr")}
        self.assertTrue(pr <= {e.group for e in sel.groups("full")})
        with self.assertRaises(selection.SelectionError):
            sel.groups("nightly")

    def test_rejections(self):
        base = {"schema_version": 1, "enabled": [{"group": "a", "scope": "pr"}]}
        cases = [
            ({**base, "enabled": [{"group": "a", "scope": "pr"}, {"group": "a", "scope": "full"}]},
             "enabled twice"),
            ({**base, "declined": [{"reason": "r", "groups": ["a"]}]}, "both enabled and declined"),
            ({**base, "enabled": [{"group": "a", "scope": "nightly"}]}, "want pr or full"),
            ({**base, "enabled": [{"group": "a", "scope": "pr", "tier": 1}]}, "unknown keys"),
            ({**base, "enabled": [{"group": "a", "scope": "pr", "timeout_s": 0}]}, "positive"),
            # isinstance(True, int) holds.
            ({**base, "enabled": [{"group": "a", "scope": "pr", "timeout_s": True}]}, "positive"),
            ({**base, "declined": [{"reason": "", "groups": ["b"]}]}, "reason and a group list"),
            ({"schema_version": 2, "enabled": []}, "schema_version"),
        ]
        for doc, fragment in cases:
            with self.assertRaises(selection.SelectionError) as cm:
                selection.parse(doc, "t.jsonc")
            self.assertIn(fragment, str(cm.exception))

    def test_resolve_ids(self):
        universe = ["fake:basic/pass", "fake:basic/fail", "fake:slow/crash"]
        chosen, errors = selection.resolve_ids(
            ["fake:basic/*", "fake:basic/pass", "fake:basic/pas", "ltp:x"], universe, "fake")
        self.assertEqual(chosen, ["fake:basic/pass", "fake:basic/fail"])
        self.assertEqual(len(errors), 2)
        self.assertIn("near: fake:basic/pass", errors[0])
        self.assertIn("not a fake id", errors[1])
        chosen, errors = selection.resolve_ids(["fake:basic"], universe, "fake")
        self.assertEqual((chosen, errors), (["fake:basic/pass", "fake:basic/fail"], []))


if __name__ == "__main__":
    unittest.main()
