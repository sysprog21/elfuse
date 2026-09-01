# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import concurrent.futures
from pathlib import Path
from typing import Callable, Dict, List, Optional

from conformance import ids, judge
from conformance.backends.base import Backend
from conformance.expectations import Expectations, Resolution
from conformance.model import Attempt, CaseResult, Invocation, Status, Verdict
from conformance.providers.base import Case, Provider

Log = Callable[[str], None]


def _relativize(inv: Invocation, root: Path) -> None:
    for name in ("stdout", "stderr"):
        value = getattr(inv, name)
        if value:
            try:
                setattr(inv, name, str(Path(value).relative_to(root)))
            except ValueError:
                pass


def _finish(case: Case, attempts: List[Attempt], resolution: Resolution,
            bootstrap: bool, results_dir: Path, backend: str) -> CaseResult:
    last = attempts[-1]
    if bootstrap:
        verdict = Verdict.ERROR if last.status is Status.ERROR else Verdict.AS_EXPECTED
        message = last.detail if verdict is Verdict.ERROR else ""
    else:
        verdict, message = judge.decide(case.id, last.status, resolution)
        if verdict is Verdict.ERROR and last.detail:
            message = "%s: %s" % (message, last.detail)
        if (resolution.quarantined and verdict.is_red
                and verdict is not Verdict.ERROR):
            verdict, message = Verdict.FLAKED, ""
        elif verdict is Verdict.AS_EXPECTED and len(attempts) > 1:
            verdict = Verdict.FLAKED
    for a in attempts:
        _relativize(a.invocation, results_dir)
    return CaseResult(
        id=case.id, suite=ids.suite_of(case.id), backend=backend, status=last.status,
        verdict=verdict, expectation=resolution.to_dict(), attempts=attempts, detail=message,
    )


def run_lane(provider: Provider, backend: Backend, cases: List[Case],
             expectations: Expectations, results_dir: Path, jobs: int = 1,
             retry: bool = True, bootstrap: bool = False,
             log: Optional[Log] = None) -> List[CaseResult]:
    log = log or (lambda _: None)
    results: Dict[str, CaseResult] = {}
    launch: List[Case] = []
    resolutions: Dict[str, Resolution] = {}
    for case in cases:
        resolution = expectations.resolve(case.id)
        resolutions[case.id] = resolution
        if resolution.type == "skip" and not bootstrap:
            results[case.id] = CaseResult(
                id=case.id, suite=ids.suite_of(case.id), backend=backend.name,
                status=Status.SKIP, verdict=Verdict.FILTERED, expectation=resolution.to_dict(),
                detail="skip: " + resolution.reason)
        else:
            launch.append(case)

    batches: Dict[str, List[Case]] = {}
    for case in launch:
        key = case.id if resolutions[case.id].quarantined else provider.batch_key(case)
        batches.setdefault(key, []).append(case)

    def run_batch(key: str) -> List[CaseResult]:
        members = batches[key]
        quarantined = resolutions[members[0].id].quarantined
        # A quarantined key holds one case; with no batch result it takes
        # the single-case path below.
        first = ({} if quarantined
                 else provider.run_batch(backend, members,
                                         results_dir / "cases" / ("batch-" + ids.slug(key))))
        out = []
        for case in members:
            case_dir = results_dir / "cases" / ids.slug(case.id)
            if case.id in first:
                attempts = [first[case.id]]
            else:
                if not quarantined:
                    log("%s: unresolved by the batch, rerunning alone" % case.id)
                attempts = [provider.run_single(backend, case, case_dir / "attempt-1")]
            resolution = resolutions[case.id]
            while (retry and not bootstrap
                   and judge.decide(case.id, attempts[-1].status, resolution)[0].is_red
                   and attempts[-1].status is not Status.ERROR
                   and judge.may_retry(resolution, len(attempts))):
                n = len(attempts) + 1
                log("%s: %s on attempt %d, quarantined, retrying" % (case.id, attempts[-1].status.value, n - 1))
                attempts.append(provider.run_single(backend, case, case_dir / ("attempt-%d" % n)))
            out.append(_finish(case, attempts, resolution, bootstrap, results_dir, backend.name))
        return out

    workers = min(jobs, backend.max_jobs or jobs)
    keys = list(batches)
    if workers > 1 and len(keys) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            batched = list(pool.map(run_batch, keys))
    else:
        batched = [run_batch(k) for k in keys]
    for group in batched:
        for r in group:
            results[r.id] = r
    return [results[c.id] for c in cases]
