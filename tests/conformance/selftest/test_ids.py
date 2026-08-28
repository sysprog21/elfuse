# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import unittest

from conformance import ids


class IdsTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(ids.parse("ltp:chmod09"), ("ltp", "chmod09", None))
        self.assertEqual(
            ids.parse("gvisor:pipe_test/Pipes/PipeTest.Count/blocking"),
            ("gvisor", "pipe_test", "Pipes/PipeTest.Count/blocking"),
        )

    def test_rejects(self):
        for bad in ("chmod09", "ltp:", "LTP:x", "gvisor:a//b", "gvisor:a/b c", ""):
            self.assertFalse(ids.is_valid(bad), bad)
            with self.assertRaises(ids.IdError):
                ids.parse(bad)

    def test_glob(self):
        universe = ["gvisor:pipe_test/A.b", "gvisor:pipe_test/A.c/p", "gvisor:open_test/A.b"]
        self.assertEqual(ids.expand(["gvisor:pipe_test/*"], universe), universe[:2])
        self.assertEqual(ids.expand(["*"], universe), universe)
        self.assertEqual(ids.suite_of("gvisor:x/*"), "gvisor")
        self.assertEqual(ids.suite_of("*"), "")

    def test_slug_unique(self):
        a, b = ids.slug("gvisor:a_test/X.y"), ids.slug("gvisor:a/test_X.y")
        self.assertNotEqual(a, b)
        self.assertRegex(a, r"^[A-Za-z0-9_.-]+$")


if __name__ == "__main__":
    unittest.main()
