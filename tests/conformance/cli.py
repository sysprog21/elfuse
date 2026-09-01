# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import contextlib
import datetime
import json
import os
import sys
import time
import unittest
from pathlib import Path
from typing import Callable, Iterator, List, Optional

from conformance import EXIT_DRIFT, EXIT_OK, EXIT_RED, EXIT_SKIP, EXIT_USAGE
from conformance import backends, expectations, jsonc, payload, providers, report
from conformance import runner, seed, selection
from conformance.backends.base import BackendError
from conformance.model import Status
from conformance.providers.base import Provider, ProviderError

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKENDS = ("elfuse", "qemu", "all")


class Stop(Exception):
    def __init__(self, code: int):
        super().__init__(code)
        self.code = code


class Cli:
    def __init__(self, repo_root: Path, out: Callable[[str], None] = print,
                 err: Optional[Callable[[str], None]] = None):
        self.repo_root = repo_root
        self.out = out
        self.err = err or out

    def fail(self, message: str) -> None:
        self.err("conformance: " + message)

    def skip(self, args: argparse.Namespace, message: str) -> int:
        self.fail(message)
        required = args.require or os.environ.get("CONF_REQUIRE") == "1"
        return EXIT_USAGE if required else EXIT_SKIP

    def provider(self, name: str) -> Provider:
        return providers.make(name, self.repo_root)

    @staticmethod
    def backend_names(name: str) -> List[str]:
        return ["qemu", "elfuse"] if name == "all" else [name]

    def make_backend(self, args: argparse.Namespace, provider: Provider, name: str,
                     verify_payload: bool = False) -> backends.Backend:
        absent = provider.prerequisites(name)
        if absent:
            raise Stop(self.skip(args, absent))
        if verify_payload:
            try:
                payload.verify(provider.payload_root(), provider.fingerprint())
            except payload.PayloadError as e:
                self.fail(str(e))
                raise Stop(EXIT_USAGE) from None
        try:
            backend = backends.make(
                name, self.repo_root, **provider.backend_options(name)
            )
        except BackendError as e:
            self.fail(str(e))
            raise Stop(EXIT_USAGE) from None
        absent = backend.prerequisites()
        if absent:
            raise Stop(self.skip(args, absent))
        return backend

    @contextlib.contextmanager
    def started(self, args: argparse.Namespace,
                backend: backends.Backend) -> Iterator[None]:
        with backend.serialize():
            try:
                backend.start()
            except BackendError as e:
                raise Stop(self.skip(args, str(e))) from None
            try:
                yield
            except BaseException:
                # A failing stop must not replace the in-flight error.
                try:
                    backend.stop()
                except BackendError as e:
                    self.fail("backend stop failed: %s" % e)
                raise
            backend.stop()

    def emit_list(self, args: argparse.Namespace, kind: str, key: str,
                  items: List, lines: List[str], **extra) -> int:
        if args.format == "json":
            self.out(json.dumps({"schema_version": 1, "kind": kind, key: items,
                                 **extra}, sort_keys=True))
        else:
            for line in lines:
                self.out(line)
        return EXIT_OK

    def suites(self, args: argparse.Namespace) -> int:
        names = sorted(providers.REGISTRY)
        return self.emit_list(args, "suite-list", "suites", names, names)

    def list_cases(self, args: argparse.Namespace) -> int:
        provider = self.provider(args.suite)
        name = "elfuse" if args.backend == "all" else args.backend
        try:
            backend = self.make_backend(args, provider, name)
            with self.started(args, backend):
                cases = provider.enumerate(
                    backend, provider.selection.groups(args.scope)
                )
        except Stop as e:
            return e.code
        except BackendError as e:
            self.fail("backend error: %s" % e)
            return EXIT_RED
        return self.emit_list(
            args, "case-list", "cases",
            [{"id": c.id, "group": c.group, "scope": c.scope,
              "timeout_s": c.timeout_s} for c in cases],
            [c.id for c in cases], suite=args.suite, scope=args.scope)

    def run(self, args: argparse.Namespace) -> int:
        provider = self.provider(args.suite)
        codes = [self.run_one(args, provider, name)
                 for name in self.backend_names(args.backend)]
        for code in (EXIT_RED, EXIT_USAGE, EXIT_SKIP):
            if code in codes:
                return code
        return EXIT_OK

    def run_one(self, args: argparse.Namespace, provider: Provider,
                backend_name: str) -> int:
        try:
            backend = self.make_backend(
                args, provider, backend_name, verify_payload=True
            )
            exps = expectations.load(
                provider.name, backend_name, provider.expectations_dir
            )
        except Stop as e:
            return e.code
        except (expectations.ExpectationError, jsonc.JsoncError) as e:
            self.fail(str(e))
            return EXIT_USAGE
        selected_scope = "full" if args.case else args.scope
        result_scope = "cases" if args.case else args.scope
        results_dir = self.results_dir(args, provider.name, backend_name)
        started = time.monotonic()
        try:
            with self.started(args, backend):
                cases = provider.enumerate(
                    backend, provider.selection.groups(selected_scope)
                )
                if args.case:
                    chosen, errors = selection.resolve_ids(
                        args.case, [c.id for c in cases], provider.name
                    )
                    for error in errors:
                        self.fail(error)
                    if errors:
                        return EXIT_USAGE
                    wanted = set(chosen)
                    cases = [case for case in cases if case.id in wanted]
                if args.dry_run:
                    for case in cases:
                        self.out(case.id)
                    return EXIT_OK
                log = self.err if args.verbose else (lambda _: None)
                results = runner.run_lane(
                    provider, backend, cases, exps, results_dir, args.jobs,
                    not args.no_retry, args.bootstrap, log
                )
                meta = {
                    "suite": provider.name,
                    "backend": backend_name,
                    "scope": result_scope,
                    "cases": list(args.case),
                    "started": datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat(timespec="seconds"),
                    "elapsed_s": round(time.monotonic() - started, 3),
                    "bootstrap": args.bootstrap,
                    "argv": sys.argv[1:],
                }
                # Written before stop(), so a failing teardown cannot lose the lane.
                report.write(results_dir, meta, results)
                for line in report.summary_lines(meta, results, results_dir):
                    self.out(line)
        except Stop as e:
            return e.code
        except BackendError as e:
            self.fail("backend error: %s" % e)
            return EXIT_RED
        if result_scope == "full" and not args.bootstrap:
            stale = exps.stale([case.id for case in cases])
            for problem in stale:
                self.fail("stale expectation, " + problem)
            if stale:
                return EXIT_USAGE
        if args.bootstrap:
            return EXIT_RED if any(
                case.status is Status.ERROR for case in results
            ) else EXIT_OK
        return EXIT_OK if report.gate(results) == "green" else EXIT_RED

    @staticmethod
    def results_dir(args: argparse.Namespace, suite: str, backend: str) -> Path:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        return Path(args.results) / suite / backend / (
            "%s-%d" % (stamp, os.getpid())
        )

    def payload_fingerprint(self, args: argparse.Namespace) -> int:
        self.out(self.provider(args.suite).fingerprint())
        return EXIT_OK

    def payload_verify(self, args: argparse.Namespace) -> int:
        provider = self.provider(args.suite)
        try:
            payload.verify(
                provider.payload_root(), args.fingerprint or provider.fingerprint()
            )
        except payload.PayloadError as e:
            self.fail(str(e))
            return EXIT_RED
        self.out("%s: verified" % provider.payload_root())
        return EXIT_OK

    def payload_build(self, args: argparse.Namespace) -> int:
        try:
            self.provider(args.suite).build_payload(force=args.force)
        except (payload.PayloadError, ProviderError) as e:
            self.fail(str(e))
            if isinstance(e, payload.PayloadError) and e.kind != "config":
                return EXIT_RED
            return EXIT_USAGE
        return EXIT_OK

    def selection_sync(self, args: argparse.Namespace) -> int:
        lines = self.provider(args.suite).regen_selection(check=args.check)
        for line in lines:
            (self.fail if args.check else self.out)(line)
        if not lines:
            self.out("%s: selection is current" % args.suite)
        return EXIT_DRIFT if args.check and lines else EXIT_OK

    def expectations_check(self, args: argparse.Namespace) -> int:
        names = [args.suite] if args.suite else sorted(providers.REGISTRY)
        problems: List[str] = []
        for name in names:
            root = self.provider(name).expectations_dir
            if root.is_dir():
                problems.extend(expectations.lint(root))
        for problem in problems:
            self.fail(problem)
        if not problems:
            self.out("expectations: valid")
        return EXIT_USAGE if problems else EXIT_OK

    def expectations_seed(self, args: argparse.Namespace) -> int:
        provider = self.provider(args.suite)
        meta, cases = report.load(Path(args.results))
        if meta.get("suite") != provider.name:
            self.fail("%s does not contain %s results" % (
                args.results, provider.name
            ))
            return EXIT_USAGE
        reason = args.reason or seed.default_reason(
            Path(args.results), str(meta.get("started", ""))[:10]
        )
        actions = seed.propose(
            cases, reason, bool(meta.get("bootstrap")),
            whole_groups=meta.get("scope") != "cases"
        )
        if not actions:
            self.out("expectations: no changes")
            return EXIT_OK
        if not args.write:
            self.out(seed.format_actions(actions).rstrip("\n"))
            return EXIT_OK
        backend = meta.get("backend")
        if not backend:
            self.fail("results name no backend")
            return EXIT_USAGE
        leaf = expectations.leaf_path(
            provider.expectations_dir, provider.name, backend
        )
        seed.append(leaf, actions)
        problems = expectations.lint(provider.expectations_dir, seeded_ok=True)
        for problem in problems:
            self.fail(problem)
        self.out("%s: appended %d actions" % (leaf, len(actions)))
        return EXIT_USAGE if problems else EXIT_OK

    def pins(self, args: argparse.Namespace) -> int:
        names = [args.suite] if args.suite else sorted(providers.REGISTRY)
        codes = [payload.refresh(self.provider(name), args.ref, args.check,
                                 self.out, self.fail) for name in names]
        for code in (EXIT_USAGE, EXIT_DRIFT):
            if code in codes:
                return code
        return EXIT_OK

    def report(self, args: argparse.Namespace) -> int:
        root = Path(args.results)
        if args.format == "markdown":
            self.out(report.markdown(root).rstrip("\n"))
            return EXIT_OK
        meta, cases = report.load(root)
        if args.format == "json":
            self.out(json.dumps(report.document(meta, cases), sort_keys=True))
        else:
            for line in report.summary_lines(meta, cases, root):
                self.out(line)
        return EXIT_OK if report.gate(cases) == "green" else EXIT_RED

    def selftest(self, args: argparse.Namespace) -> int:
        suite = unittest.defaultTestLoader.discover(
            str(self.repo_root / "tests" / "conformance" / "selftest"),
            top_level_dir=str(self.repo_root / "tests"),
        )
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        return EXIT_OK if result.wasSuccessful() else EXIT_RED


def common_run(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--backend", choices=BACKENDS, default="elfuse")
    parser.add_argument("--results", default="build/conformance")
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--require", action="store_true")
    parser.add_argument("--no-retry", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")


def command(parent: argparse._SubParsersAction, name: str, handler: str):
    parser = parent.add_parser(name)
    parser.set_defaults(handler=handler)
    return parser


def family(parent: argparse._SubParsersAction, name: str):
    parser = parent.add_parser(name)
    return parser.add_subparsers(dest=name + "_command", required=True)


def suite_arg(parser: argparse.ArgumentParser, suites: List[str]) -> None:
    parser.add_argument("suite", choices=suites)


def build_parser(suites: List[str]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="conformance",
        description="Run registered Linux test suites on elfuse or QEMU.",
    )
    top = parser.add_subparsers(dest="command", required=True)
    p = command(top, "suites", "suites")
    p.add_argument("--format", choices=("text", "json"), default="text")

    p = command(top, "list", "list_cases")
    suite_arg(p, suites)
    p.add_argument("--scope", choices=selection.SCOPES, default="full")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--backend", choices=BACKENDS, default="elfuse")
    p.add_argument("--require", action="store_true")

    p = command(top, "run", "run")
    suite_arg(p, suites)
    p.add_argument("--scope", choices=selection.SCOPES, default="pr")
    p.add_argument("--case", action="append", default=[])
    common_run(p)

    sub = family(top, "payload")
    p = command(sub, "fingerprint", "payload_fingerprint")
    suite_arg(p, suites)
    p = command(sub, "build", "payload_build")
    suite_arg(p, suites)
    p.add_argument("--force", action="store_true")
    p = command(sub, "verify", "payload_verify")
    suite_arg(p, suites)
    p.add_argument("--fingerprint")

    sub = family(top, "selection")
    for name, check in (("check", True), ("update", False)):
        p = command(sub, name, "selection_sync")
        p.set_defaults(check=check)
        suite_arg(p, suites)

    sub = family(top, "expectations")
    p = command(sub, "check", "expectations_check")
    p.add_argument("suite", nargs="?", choices=suites)
    p = command(sub, "seed", "expectations_seed")
    suite_arg(p, suites)
    p.add_argument("results")
    p.add_argument("--reason")
    p.add_argument("--write", action="store_true")

    sub = family(top, "pins")
    p = command(sub, "check", "pins")
    p.set_defaults(check=True)
    p.add_argument("suite", nargs="?", choices=suites)
    p.add_argument("--ref")
    p = command(sub, "update", "pins")
    p.set_defaults(check=False)
    suite_arg(p, suites)
    p.add_argument("--ref")

    p = command(top, "report", "report")
    p.add_argument("results")
    p.add_argument("--format", choices=("text", "markdown", "json"),
                   default="text")
    command(top, "selftest", "selftest")
    return parser


def main(argv: Optional[List[str]] = None, repo_root: Path = REPO_ROOT,
         out: Callable[[str], None] = print,
         err: Optional[Callable[[str], None]] = None) -> int:
    parser = build_parser(sorted(providers.REGISTRY))
    args = parser.parse_args(argv)
    if err is None:
        err = lambda message: print(message, file=sys.stderr)
    cli = Cli(repo_root, out, err)
    try:
        return getattr(cli, args.handler)(args)
    except (ProviderError, selection.SelectionError, payload.PinError,
            jsonc.JsoncError, expectations.ExpectationError, report.ReportError,
            seed.SeedError) as e:
        cli.fail(str(e))
        return EXIT_USAGE
    except NotImplementedError as e:
        cli.fail(str(e) or "operation is not supported")
        return EXIT_USAGE
