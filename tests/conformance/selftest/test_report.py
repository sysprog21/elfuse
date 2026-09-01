# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import json
import unittest
from pathlib import Path

from conformance import report
from conformance.selftest.fixture import TempDirTest
from conformance.model import Attempt, CaseResult, Invocation, Status, Verdict


def case(cid, status, verdict, detail=""):
    inv = Invocation("normal", 1500, exit_code=0 if status is Status.PASS else 1)
    return CaseResult(cid, "fake", "host", status, verdict, {"type": "expect_pass"},
                      [Attempt(status, inv)], detail)


class ReportTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.meta = {"suite": "fake", "backend": "host", "scope": "pr", "elapsed_s": 61.4}

    def test_empty_is_red(self):
        self.assertEqual(report.gate([]), "red")
        lines = report.summary_lines(self.meta, [], self.dir)
        self.assertIn("  RED no cases ran", lines)
        self.assertTrue(lines[-1].startswith("RESULT: RED"))

    def test_round_trip_and_summary(self):
        cases = [case("fake:b/p", Status.PASS, Verdict.AS_EXPECTED),
                 case("fake:b/f", Status.FAIL, Verdict.UNEXPECTED_FAILURE, "fake:b/f: FAIL \x01 raw")]
        report.write(self.dir, self.meta, cases)
        meta, again = report.load(self.dir)
        self.assertEqual(again, cases)
        self.assertEqual(meta["scope"], "pr")
        text = (self.dir / "summary.txt").read_text()
        self.assertIn("conformance fake/host pr: 2 cases in 1m01s", text)
        self.assertIn("  unexpected_failure 1  unexpected_pass 0  error 0", text)
        self.assertIn("  RED fake:b/f: FAIL", text)
        self.assertIn("RESULT: RED", text)
        doc = json.loads((self.dir / report.RESULTS).read_text())
        self.assertEqual(doc["kind"], "run")

    def test_contradiction_is_rejected(self):
        report.write(self.dir, self.meta, [case("fake:b/p", Status.PASS, Verdict.AS_EXPECTED)])
        doc = json.loads((self.dir / report.RESULTS).read_text())
        doc["gate"] = "red"
        (self.dir / report.RESULTS).write_text(json.dumps(doc))
        with self.assertRaises(report.ReportError):
            report.load(self.dir)

    def test_a_wrong_shape_is_rejected(self):
        for text in ("[]", '{"schema_version": 1, "kind": "run", '
                     '"cases": null, "run": {}}',
                     '{"schema_version": 1, "kind": "run", '
                     '"cases": [], "run": []}',
                     '{"schema_version": 1, "kind": "run", '
                     '"cases": ["x"], "run": {}}'):
            (self.dir / report.RESULTS).write_text(text)
            with self.assertRaises(report.ReportError, msg=text):
                report.load(self.dir)

    def test_markdown(self):
        report.write(self.dir / "fake" / "host" / "1", self.meta,
                     [case("fake:b/p", Status.PASS, Verdict.AS_EXPECTED)])
        bad = self.dir / "fake" / "host" / "2"
        bad.mkdir(parents=True)
        (bad / report.RESULTS).write_text('{"schema_version": 1}')
        worse = self.dir / "fake" / "host" / "3"
        worse.mkdir(parents=True)
        (worse / report.RESULTS).write_text("[]")
        text = report.markdown(self.dir)
        self.assertIn("| fake/host | pr | green | 1 | 0 | 0 | 0 |", text)
        self.assertEqual(text.count("| error |"), 2)
        self.assertIn("no conformance results", report.markdown(self.dir / "none"))


if __name__ == "__main__":
    unittest.main()
