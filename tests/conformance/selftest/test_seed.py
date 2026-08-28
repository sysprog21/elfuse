# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import tempfile
import unittest
from pathlib import Path

from conformance import expectations, jsonc, seed
from conformance.model import Attempt, CaseResult, Invocation, Status, Verdict


def case(cid, status, verdict=Verdict.AS_EXPECTED, expectation="expect_pass"):
    inv = Invocation("normal", 1, exit_code=0)
    return CaseResult(cid, "s", "b", status, verdict, {"type": expectation}, [Attempt(status, inv)])


class SeedTest(unittest.TestCase):
    def test_bootstrap_collapses_whole_groups(self):
        cases = [case("s:a/1", Status.FAIL), case("s:a/2", Status.BROK),
                 case("s:b/1", Status.FAIL), case("s:b/2", Status.PASS),
                 case("s:c/1", Status.CONF), case("s:d/1", Status.TIMEOUT), case("s:d/2", Status.CRASH),
                 case("s:e/1", Status.PASS), case("s:e/2", Status.SKIP)]
        actions = seed.propose(cases, "r", bootstrap=True)
        self.assertEqual(actions, [
            {"type": "expect_failure", "reason": "r", "matchers": ["s:a/*", "s:b/1"]},
            {"type": "expect_conf", "reason": "r", "matchers": ["s:c/1"]},
            {"type": "skip", "reason": "r", "matchers": ["s:d/*"]},
        ])

    def test_a_partial_group_never_collapses(self):
        cases = [case("s:a/1", Status.FAIL, Verdict.UNEXPECTED_FAILURE),
                 case("s:a/2", Status.FAIL, Verdict.UNEXPECTED_FAILURE)]
        self.assertEqual(seed.propose(cases, "r", False, whole_groups=False)[0]["matchers"],
                         ["s:a/1", "s:a/2"])

    def test_bootstrap_ignores_what_an_earlier_leaf_recorded(self):
        cases = [case("s:a/1", Status.FAIL, expectation="expect_failure"), case("s:a/2", Status.FAIL)]
        self.assertEqual(seed.propose(cases, "r", True),
                         [{"type": "expect_failure", "reason": "r", "matchers": ["s:a/*"]}])

    def test_gated_seeds_only_reds(self):
        cases = [case("s:a/1", Status.PASS, Verdict.UNEXPECTED_PASS, "expect_failure"),
                 case("s:a/2", Status.FAIL, Verdict.AS_EXPECTED, "expect_failure"),
                 case("s:b/1", Status.FAIL, Verdict.UNEXPECTED_FAILURE)]
        self.assertEqual(seed.propose(cases, "r", False), [
            {"type": "expect_pass", "reason": "r", "matchers": ["s:a/1"]},
            {"type": "expect_failure", "reason": "r", "matchers": ["s:b/1"]},
        ])

    def test_error_refused(self):
        with self.assertRaises(ValueError):
            seed.propose([case("s:a/1", Status.ERROR, Verdict.ERROR)], "r", True)

    def test_append_keeps_header_and_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "s.jsonc").write_text('{"actions":[{"type":"expect_pass","matchers":["*"]}]}')
            leaf = root / "s_b.jsonc"
            leaf.write_text('// head\n// two\n{\n  "actions": [\n    { "include": "s.jsonc" }, // inline\n  ],\n}\n')
            seed.append(leaf, [{"type": "skip", "reason": "r", "since": "2026-08-25", "matchers": ["s:a/1", "s:a/2"]}])
            text = leaf.read_text()
            self.assertTrue(text.startswith("// head\n// two\n{"))
            self.assertNotIn("inline", text)
            self.assertEqual(jsonc.loads(text)["actions"][0], {"include": "s.jsonc"})
            e = expectations.load("s", "b", root)
            self.assertEqual(e.resolve("s:a/2").type, "skip")
            self.assertEqual(expectations.lint(root), [])

    def test_append_creates_a_loadable_leaf(self):
        action = {"type": "skip", "reason": "r", "matchers": ["s:a/1"]}
        for base in (True, False):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                if base:
                    (root / "s.jsonc").write_text('{"actions":[{"type":"expect_pass","matchers":["*"]}]}')
                seed.append(root / "s_b.jsonc", [action])
                first = jsonc.loads((root / "s_b.jsonc").read_text())["actions"][0]
                self.assertEqual(first, {"include": "s.jsonc"} if base
                                 else {"type": "expect_pass", "matchers": ["*"]})
                self.assertEqual(expectations.load("s", "b", root).resolve("s:a/1").type, "skip")


if __name__ == "__main__":
    unittest.main()
