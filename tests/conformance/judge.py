# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Tuple

from conformance.expectations import Resolution
from conformance.model import Status, Verdict

MAX_ATTEMPTS = 3

_SATISFIES = {
    "expect_pass": (Status.PASS, Status.WARN),
    "expect_failure": (Status.FAIL, Status.BROK),
    "expect_conf": (Status.CONF,),
}


def decide(test_id: str, status: Status, resolution: Resolution) -> Tuple[Verdict, str]:
    if status is Status.ERROR:
        return Verdict.ERROR, "%s: HARNESS ERROR, the case did not run" % test_id
    if status is Status.SKIP:
        return Verdict.FILTERED, ""
    if status in (Status.TIMEOUT, Status.CRASH, Status.INCONSISTENT):
        return (
            Verdict.UNEXPECTED_FAILURE,
            "%s: %s, which no expectation can satisfy" % (test_id, status.value),
        )
    if status in _SATISFIES[resolution.type]:
        return Verdict.AS_EXPECTED, ""
    if status in _SATISFIES["expect_pass"]:
        return (
            Verdict.UNEXPECTED_PASS,
            "%s: %s but %s expects %s (matcher %r); narrow or delete that "
            "matcher in this same change" % (
                test_id, status.value, resolution.source, resolution.type,
                resolution.matcher),
        )
    return (
        Verdict.UNEXPECTED_FAILURE,
        "%s: %s but %s expects %s (matcher %r); fix the regression or record "
        "the divergence in the backend leaf" % (
            test_id, status.value, resolution.source, resolution.type,
            resolution.matcher),
    )


def may_retry(resolution: Resolution, attempts: int) -> bool:
    return resolution.quarantined and attempts < MAX_ATTEMPTS
