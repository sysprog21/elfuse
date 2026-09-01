# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import unittest
from pathlib import Path

from conformance import expectations, report, runner
from conformance.model import Status, Verdict
from conformance.selftest.fixture import FixtureProvider, LocalBackend, TempDirTest, setup


class RunnerTest(TempDirTest):
    def setUp(self):
        super().setUp()
        setup(self.root)
        self.provider = FixtureProvider(self.root)
        self.backend = LocalBackend()
        self.exps = expectations.load(
            "fixture", "elfuse", self.provider.expectations_dir
        )
        self.log = []

    def lane(self, scope, **kwargs):
        cases = self.provider.enumerate(
            self.backend, self.provider.selection.groups(scope)
        )
        results = runner.run_lane(
            self.provider, self.backend, cases, self.exps, self.root / "results",
            log=self.log.append, **kwargs
        )
        return {result.id: result for result in results}

    def test_pr_scope_is_green(self):
        results = self.lane("pr")
        self.assertEqual(report.gate(results.values()), "green")
        self.assertEqual(
            results["fixture:basic/fail"].verdict, Verdict.AS_EXPECTED
        )
        flaky = results["fixture:basic/flaky"]
        self.assertEqual(flaky.verdict, Verdict.FLAKED)
        self.assertEqual(
            [attempt.status for attempt in flaky.attempts],
            [Status.FAIL, Status.PASS],
        )
        quarantined = results["fixture:basic/quarantined"]
        self.assertEqual(quarantined.verdict, Verdict.FLAKED)
        self.assertEqual(
            [attempt.status for attempt in quarantined.attempts],
            [Status.FAIL, Status.FAIL, Status.FAIL],
        )

    def test_no_retry_keeps_quarantine_non_gating(self):
        result = self.lane("pr", retry=False)["fixture:basic/flaky"]
        self.assertEqual(result.verdict, Verdict.FLAKED)
        self.assertEqual(len(result.attempts), 1)

    def test_unresolved_batch_case_runs_alone(self):
        result = self.lane("full")["fixture:slow/unresolved"]
        self.assertEqual(result.verdict, Verdict.AS_EXPECTED)
        self.assertTrue(any("rerunning alone" in line for line in self.log))

    def test_bootstrap_records_without_expectations(self):
        results = self.lane("pr", bootstrap=True)
        self.assertEqual(report.gate(results.values()), "green")
        self.assertEqual(
            results["fixture:basic/fail"].verdict, Verdict.AS_EXPECTED
        )
        self.assertEqual(len(results["fixture:basic/flaky"].attempts), 1)


if __name__ == "__main__":
    unittest.main()
