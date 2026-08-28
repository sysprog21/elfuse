# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import tempfile
import unittest
from pathlib import Path

from conformance import expectations, providers, report, runner
from conformance.backends.host import HostBackend
from conformance.model import Status, Verdict

REPO = Path(__file__).resolve().parents[3]


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.results = Path(self.tmp.name)
        self.provider = providers.make("fake", REPO)
        self.backend = HostBackend(REPO)
        self.exps = expectations.load("fake", "host", self.provider.expectations_dir)
        self.log = []

    def tearDown(self):
        self.tmp.cleanup()

    def lane(self, scope, **kw):
        cases = self.provider.enumerate(self.backend, self.provider.selection.groups(scope))
        return {r.id: r for r in runner.run_lane(
            self.provider, self.backend, cases, self.exps, self.results, log=self.log.append, **kw)}

    def test_pr_scope_is_green(self):
        by_id = self.lane("pr")
        self.assertEqual(report.gate(by_id.values()), "green", [r.detail for r in by_id.values()])
        self.assertEqual(by_id["fake:basic/pass"].verdict, Verdict.AS_EXPECTED)
        self.assertEqual(by_id["fake:basic/fail"].verdict, Verdict.AS_EXPECTED)
        self.assertEqual(by_id["fake:basic/conf"].status, Status.CONF)
        self.assertEqual(by_id["fake:basic/warn"].verdict, Verdict.AS_EXPECTED)
        skipped = by_id["fake:basic/skipped"]
        self.assertEqual((skipped.status, skipped.verdict, skipped.attempts), (Status.SKIP, Verdict.FILTERED, []))
        self.assertEqual(self.provider.runs.get("fake:basic/skipped"), None)

    def test_flake_is_retried_and_measured(self):
        r = self.lane("pr")["fake:basic/flaky"]
        self.assertEqual(r.verdict, Verdict.FLAKED)
        self.assertEqual([a.status for a in r.attempts], [Status.FAIL, Status.PASS])
        self.assertTrue(all(a.invocation.wall_us > 0 for a in r.attempts))
        self.assertEqual(r.attempts[0].invocation.exit_code, 1)
        self.assertTrue((self.results / r.attempts[1].invocation.stdout).is_file())
        self.assertFalse(Path(r.attempts[1].invocation.stdout).is_absolute())
        self.assertTrue(any("quarantined, retrying" in line for line in self.log))

    def test_no_retry_flag(self):
        r = self.lane("pr", retry=False)["fake:basic/flaky"]
        self.assertEqual(r.verdict, Verdict.UNEXPECTED_FAILURE)
        self.assertEqual(len(r.attempts), 1)

    def test_full_scope_reds(self):
        by_id = self.lane("full", jobs=3)
        self.assertEqual(report.gate(by_id.values()), "red")
        self.assertEqual(by_id["fake:slow/timeout"].status, Status.TIMEOUT)
        self.assertEqual(by_id["fake:slow/timeout"].verdict, Verdict.UNEXPECTED_FAILURE)
        self.assertIsNone(by_id["fake:slow/timeout"].attempts[0].invocation.exit_code)
        self.assertEqual(by_id["fake:slow/crash"].status, Status.CRASH)
        self.assertEqual(by_id["fake:slow/crash"].attempts[0].invocation.signal, 11)
        unresolved = by_id["fake:slow/unresolved"]
        self.assertEqual(unresolved.verdict, Verdict.AS_EXPECTED)
        self.assertTrue(any("unresolved by the batch" in line for line in self.log))
        recorded = by_id["fake:recorded/passes"]
        self.assertEqual(recorded.verdict, Verdict.UNEXPECTED_PASS)
        self.assertIn("narrow or delete that matcher", recorded.detail)
        self.assertIn("fake:narrow/keep", by_id)
        self.assertNotIn("fake:narrow/drop", by_id)

    def test_bootstrap_records_without_judging(self):
        by_id = self.lane("full", bootstrap=True)
        self.assertEqual(report.gate(by_id.values()), "green")
        self.assertEqual(by_id["fake:slow/crash"].verdict, Verdict.AS_EXPECTED)
        self.assertEqual(by_id["fake:basic/skipped"].status, Status.PASS)
        self.assertEqual(len(by_id["fake:basic/flaky"].attempts), 1)


if __name__ == "__main__":
    unittest.main()
