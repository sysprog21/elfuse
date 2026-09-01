# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import unittest

from conformance.model import Attempt, CaseResult, Invocation, Status, Verdict


class ModelTest(unittest.TestCase):
    def test_round_trip(self):
        inv = Invocation(execution="signal", wall_us=1234, signal=11, stdout="cases/x/stdout")
        att = Attempt(status=Status.CRASH, invocation=inv, detail="SIGSEGV")
        case = CaseResult(
            id="fake:basic/crash",
            suite="fake",
            backend="host",
            status=Status.CRASH,
            verdict=Verdict.UNEXPECTED_FAILURE,
            expectation={"type": "expect_pass"},
            attempts=[att],
        )
        again = CaseResult.from_dict(case.to_dict())
        self.assertEqual(again, case)
        self.assertEqual(again.attempts[0].invocation.exit_code, None)

    def test_execution_is_checked(self):
        with self.assertRaises(ValueError):
            Invocation(execution="lost", wall_us=0)
        with self.assertRaises(ValueError):
            Invocation(execution="normal", wall_us=-1)

    def test_execution_decides_which_field_is_set(self):
        Invocation(execution="normal", wall_us=0, exit_code=0)
        Invocation(execution="signal", wall_us=0, signal=11)
        Invocation(execution="timeout", wall_us=0)
        Invocation(execution="transport", wall_us=0)
        for kwargs in ({"execution": "normal", "signal": 11},
                       {"execution": "normal"},
                       {"execution": "signal", "exit_code": 0},
                       {"execution": "timeout", "exit_code": 3},
                       {"execution": "transport", "signal": 9}):
            with self.assertRaises(ValueError):
                Invocation(wall_us=0, **kwargs)

    def test_red_verdicts(self):
        red = {v for v in Verdict if v.is_red}
        self.assertEqual(
            red, {Verdict.UNEXPECTED_FAILURE, Verdict.UNEXPECTED_PASS, Verdict.ERROR}
        )


if __name__ == "__main__":
    unittest.main()
