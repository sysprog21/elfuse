# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import unittest

from conformance import judge
from conformance.expectations import Resolution
from conformance.model import Status, Verdict


def res(kind, quarantined=False):
    return Resolution(kind, "why", "s_b.jsonc:1", "s:a", quarantined)


class JudgeTest(unittest.TestCase):
    def test_table(self):
        table = [
            ("expect_pass", Status.PASS, Verdict.AS_EXPECTED),
            ("expect_pass", Status.WARN, Verdict.AS_EXPECTED),
            ("expect_pass", Status.FAIL, Verdict.UNEXPECTED_FAILURE),
            ("expect_pass", Status.CONF, Verdict.UNEXPECTED_FAILURE),
            ("expect_failure", Status.FAIL, Verdict.AS_EXPECTED),
            ("expect_failure", Status.BROK, Verdict.AS_EXPECTED),
            ("expect_failure", Status.PASS, Verdict.UNEXPECTED_PASS),
            ("expect_failure", Status.WARN, Verdict.UNEXPECTED_PASS),
            ("expect_conf", Status.CONF, Verdict.AS_EXPECTED),
            ("expect_conf", Status.PASS, Verdict.UNEXPECTED_PASS),
            ("expect_conf", Status.WARN, Verdict.UNEXPECTED_PASS),
            ("expect_conf", Status.FAIL, Verdict.UNEXPECTED_FAILURE),
            ("expect_pass", Status.SKIP, Verdict.FILTERED),
            ("expect_failure", Status.SKIP, Verdict.FILTERED),
            ("expect_pass", Status.ERROR, Verdict.ERROR),
        ]
        for kind, status, want in table:
            verdict, _ = judge.decide("s:a", status, res(kind))
            self.assertEqual(verdict, want, (kind, status))

    def test_never_satisfiable(self):
        for status in (Status.TIMEOUT, Status.CRASH, Status.INCONSISTENT):
            for kind in ("expect_pass", "expect_failure", "expect_conf"):
                verdict, msg = judge.decide("s:a", status, res(kind))
                self.assertEqual(verdict, Verdict.UNEXPECTED_FAILURE)
                self.assertIn("no expectation can satisfy", msg)

    def test_messages_name_the_matcher(self):
        _, msg = judge.decide("s:a", Status.PASS, res("expect_failure"))
        self.assertEqual(
            msg,
            "s:a: PASS but s_b.jsonc:1 expects expect_failure (matcher 's:a'); "
            "narrow or delete that matcher in this same change",
        )
        _, msg = judge.decide("s:a", Status.FAIL, res("expect_pass"))
        self.assertIn("record the divergence in the backend leaf", msg)

    def test_retry_only_quarantined(self):
        self.assertFalse(judge.may_retry(res("expect_pass"), 1))
        self.assertTrue(judge.may_retry(res("expect_pass", True), 1))
        self.assertTrue(judge.may_retry(res("expect_pass", True), 2))
        self.assertFalse(judge.may_retry(res("expect_pass", True), 3))


if __name__ == "__main__":
    unittest.main()
