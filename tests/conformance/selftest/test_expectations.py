# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import tempfile
import unittest
from pathlib import Path

from conformance import expectations as ex

ROOT = Path(__file__).resolve().parents[1] / "expectations"


def write(root, name, text):
    (root / name).write_text(text)


class ShippedFilesTest(unittest.TestCase):
    def test_lint_clean(self):
        self.assertEqual(ex.lint(ROOT), [])

    def test_resolve_fake_host(self):
        e = ex.load("fake", "host", ROOT)
        self.assertEqual(e.resolve("fake:basic/pass").type, "expect_pass")
        r = e.resolve("fake:basic/fail")
        self.assertEqual((r.type, r.matcher), ("expect_failure", "fake:basic/fail"))
        self.assertEqual(e.resolve("fake:basic/skipped").type, "skip")
        flaky = e.resolve("fake:basic/flaky")
        self.assertEqual(flaky.type, "expect_pass")
        self.assertTrue(flaky.quarantined)
        self.assertFalse(e.resolve("fake:basic/pass").quarantined)

    def test_stale(self):
        e = ex.load("fake", "host", ROOT)
        stale = e.stale(["fake:basic/pass", "fake:basic/fail", "fake:basic/conf",
                         "fake:basic/skipped", "fake:basic/flaky"])
        self.assertEqual(len(stale), 1)
        self.assertIn("recorded/passes", stale[0])


class LintTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root, "s.jsonc", '{"actions":[{"type":"expect_pass","matchers":["*"]}]}')

    def tearDown(self):
        self.tmp.cleanup()

    def leaf(self, body):
        write(self.root, "s_b.jsonc", '{"actions":[{"include":"s.jsonc"},%s]}' % body)
        return ex.lint(self.root)

    def test_clean(self):
        self.assertEqual(self.leaf(""), [])

    def test_first_action(self):
        write(self.root, "s_b.jsonc",
              '{"actions":[{"type":"skip","reason":"r","matchers":["s:a"]}]}')
        self.assertIn("first effective action", ex.lint(self.root)[0])

    def test_rules(self):
        cases = {
            "needs a reason": '{"type":"expect_failure","matchers":["s:a"]}',
            "not sorted": '{"type":"skip","reason":"r","matchers":["s:b","s:a"]}',
            "not in suite s": '{"type":"skip","reason":"r","matchers":["t:a"]}',
            "unknown keys": '{"type":"skip","reason":"r","matchers":["s:a"],"bug":"#1"}',
            "unknown action type": '{"type":"xfail","reason":"r","matchers":["s:a"]}',
            "legal only in flaky": '{"type":"quarantine","reason":"r","matchers":["s:a"]}',
            "tracking must be": '{"type":"skip","reason":"r","matchers":["s:a"],"tracking":"1"}',
            "since must be": '{"type":"skip","reason":"r","matchers":["s:a"],"since":"x"}',
            "em dash": '{"type":"skip","reason":"a \\u2014 b","matchers":["s:a"]}',
            "legal only on expect_pass": '{"type":"skip","reason":"r","matchers":["*"]}',
        }
        for fragment, body in cases.items():
            problems = self.leaf(body)
            self.assertEqual(len(problems), 1, (fragment, problems))
            self.assertIn(fragment, problems[0])

    def test_seeded_reason_is_reported(self):
        problems = self.leaf(
            '{"type":"expect_failure","reason":"seeded from x on 2026-01-01; untriaged",'
            '"matchers":["s:a"]}')
        self.assertEqual(len(problems), 1)
        self.assertIn("seeded reason", problems[0])

    def test_include_cycle(self):
        write(self.root, "s.jsonc", '{"actions":[{"include":"s_b.jsonc"}]}')
        self.assertIn("include cycle", self.leaf("")[0])

    def test_last_match_wins(self):
        self.leaf('{"type":"skip","reason":"r","matchers":["s:g/*"]},'
                  '{"type":"expect_failure","reason":"r","matchers":["s:g/one"]}')
        e = ex.load("s", "b", self.root)
        self.assertEqual(e.resolve("s:g/one").type, "expect_failure")
        self.assertEqual(e.resolve("s:g/two").type, "skip")
        self.assertEqual(e.resolve("s:h").type, "expect_pass")

    def test_flaky_matchers_are_validated_not_indexed(self):
        self.leaf("")
        for value in ("[]", "null", "[7]"):
            write(self.root, "flaky.jsonc",
                  '{"actions":[{"type":"quarantine","reason":"r","matchers":%s}]}' % value)
            self.assertIn("matchers must be", ex.lint(self.root)[0])

    def test_flaky_only_quarantine(self):
        self.leaf("")
        write(self.root, "flaky.jsonc",
              '{"actions":[{"type":"skip","reason":"r","matchers":["s:a"]}]}')
        self.assertIn("holds only quarantine", ex.lint(self.root)[0])


if __name__ == "__main__":
    unittest.main()
