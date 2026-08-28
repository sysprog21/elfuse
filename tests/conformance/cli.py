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

from conformance import backends, expectations, jsonc, payload, providers, report, runner, seed
from conformance import selection as selection_mod
from conformance import update as update_mod
from conformance.backends.base import BackendError
from conformance.model import Status
from conformance.providers.base import ProviderError

EXIT_OK, EXIT_RED, EXIT_USAGE, EXIT_SKIP = 0, 1, 2, 77
_SEVERITY = {EXIT_RED: 3, EXIT_USAGE: 2, EXIT_SKIP: 1, EXIT_OK: 0}
REPO_ROOT = Path(__file__).resolve().parents[2]
BACKENDS = ("elfuse", "qemu", "all", "host")


def worst_of(codes) -> int:
    return max(codes, key=lambda c: _SEVERITY.get(c, 3), default=EXIT_OK)


class _Exit(Exception):
    def __init__(self, code: int):
        super().__init__(code)
        self.code = code


class Cli:
    def __init__(self, repo_root: Path, out: Callable[[str], None] = print):
        self.repo_root = repo_root
        self.out = out

    def skip(self, args: argparse.Namespace, message: str) -> int:
        self.out(message)
        required = args.require or os.environ.get("CONF_REQUIRE") == "1"
        return EXIT_USAGE if required else EXIT_SKIP

    def provider(self, name: str) -> providers.Provider:
        return providers.make(name, self.repo_root)

    @staticmethod
    def backend_names(args: argparse.Namespace) -> List[str]:
        return ["qemu", "elfuse"] if args.backend == "all" else [args.backend]

    def run(self, args: argparse.Namespace) -> int:
        provider = self.provider(args.suite)
        return worst_of(self.run_one(args, provider, name) for name in self.backend_names(args))

    def make_backend(self, args: argparse.Namespace, provider: providers.Provider, name: str,
                     verify_payload: bool = False) -> backends.Backend:
        absent = provider.prerequisites(name)
        if absent:
            raise _Exit(self.skip(args, absent))
        if verify_payload:
            try:
                payload.verify(provider.payload_root(), provider.fingerprint())
            except NotImplementedError:
                pass
            except payload.PayloadError as e:
                # Manifest corruption is an error, not an absent prerequisite.
                self.out("conformance: %s" % e)
                raise _Exit(EXIT_USAGE) from None
        try:
            backend = backends.make(name, self.repo_root, **provider.backend_options(name))
        except BackendError as e:
            self.out("conformance: %s" % e)
            raise _Exit(EXIT_USAGE) from None
        absent = backend.prerequisites()
        if absent:
            raise _Exit(self.skip(args, "conformance: " + absent))
        return backend

    @contextlib.contextmanager
    def started(self, args: argparse.Namespace, backend: backends.Backend) -> Iterator[None]:
        """Hold backend serialization across start, use, and stop."""
        with backend.serialize():
            try:
                backend.start()
            except BackendError as e:
                raise _Exit(self.skip(args, "conformance: %s" % e)) from None
            try:
                yield
            finally:
                backend.stop()

    def run_one(self, args: argparse.Namespace, provider: providers.Provider, name: str) -> int:
        try:
            backend = self.make_backend(args, provider, name, verify_payload=True)
        except _Exit as e:
            return e.code
        try:
            exps = expectations.load(provider.name, name, provider.expectations_dir)
        except ValueError as e:  # ExpectationError included
            self.out("conformance: %s" % e)
            return EXIT_USAGE
        scope = "full" if args.scope == "test" else args.scope
        entries = provider.selection.groups(scope)
        results_dir = self.results_dir(args, provider.name, name)
        started = time.monotonic()
        try:
            with self.started(args, backend):
                cases = provider.enumerate(backend, entries)
                if args.scope == "test":
                    chosen, errors = selection_mod.resolve_ids(args.ids, [c.id for c in cases], provider.name)
                    for e in errors:
                        self.out("conformance: " + e)
                    if errors:
                        return EXIT_USAGE
                    wanted = set(chosen)
                    cases = [c for c in cases if c.id in wanted]
                if args.dry_run:
                    for c in cases:
                        self.out(c.id)
                    return EXIT_OK
                log = self.out if args.verbose else (lambda _: None)
                results = runner.run_lane(provider, backend, cases, exps, results_dir,
                                          args.jobs, not args.no_retry, args.bootstrap, log)
            meta = {
                "suite": provider.name, "backend": name, "scope": args.scope,
                "ids": list(args.ids),
                "started": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "elapsed_s": round(time.monotonic() - started, 3),
                "bootstrap": args.bootstrap, "argv": sys.argv[1:],
            }
            report.write(results_dir, meta, results)
            self.link_latest(results_dir)
            for line in report.summary_lines(meta, results, results_dir):
                self.out(line)
        except _Exit as e:
            return e.code
        except BackendError as e:
            self.out("conformance: backend error: %s" % e)
            return EXIT_RED
        if os.environ.get("GITHUB_ACTIONS") == "true":
            for c in results:
                if c.verdict.is_red:
                    self.out("::error title=conformance::%s"
                             % report.red_line(c).splitlines()[0])
        if args.scope == "full" and not args.bootstrap:
            stale = exps.stale([c.id for c in cases])
            for s in stale:
                self.out("conformance: stale expectation, " + s)
            if stale:
                return EXIT_USAGE
        if args.bootstrap:
            return EXIT_RED if any(c.status is Status.ERROR for c in results) else EXIT_OK
        return EXIT_OK if report.gate(results) == "green" else EXIT_RED

    def results_dir(self, args: argparse.Namespace, suite: str, backend: str) -> Path:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return Path(args.results) / suite / backend / ("%s-%d" % (stamp, os.getpid()))

    @staticmethod
    def link_latest(results_dir: Path) -> None:
        link = results_dir.parent / "latest"
        try:
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(results_dir.name)
        except OSError:
            pass

    def list_ids(self, args: argparse.Namespace) -> int:
        provider = self.provider(args.suite)
        # Listing through "all" uses elfuse and never boots QEMU.
        try:
            backend = self.make_backend(args, provider, self.backend_names(args)[-1])
            with self.started(args, backend):
                cases = provider.enumerate(backend, provider.selection.groups(args.scope))
        except _Exit as e:
            return e.code
        except BackendError as e:
            self.out("conformance: backend error: %s" % e)
            return EXIT_RED
        if args.json:
            self.out(json.dumps([{"id": c.id, "group": c.group, "scope": c.scope,
                                  "timeout_s": c.timeout_s} for c in cases], indent=1))
        else:
            for c in cases:
                self.out(c.id)
        return EXIT_OK

    def seed(self, args: argparse.Namespace) -> int:
        provider = self.provider(args.suite)
        try:
            meta, cases = report.load(Path(args.results_dir))
        except (ValueError, KeyError) as e:  # ReportError included
            self.out("conformance: %s" % e)
            return EXIT_USAGE
        if meta.get("suite") != provider.name:
            self.out("conformance: %s holds %s results, not %s" % (args.results_dir, meta.get("suite"), provider.name))
            return EXIT_USAGE
        reason = args.reason or seed.default_reason(Path(args.results_dir), str(meta.get("started", ""))[:10])
        try:
            # Named ids do not prove that the run covered a complete group.
            actions = seed.propose(cases, reason, bool(meta.get("bootstrap")),
                                   whole_groups=meta.get("scope") != "test")
        except ValueError as e:
            self.out("conformance: %s" % e)
            return EXIT_USAGE
        if not actions:
            self.out("conformance: nothing to seed; every case is as expected")
            return EXIT_OK
        if args.write:
            if not meta.get("backend"):
                self.out("conformance: %s names no backend" % args.results_dir)
                return EXIT_USAGE
            leaf = expectations.leaf_path(provider.expectations_dir, provider.name, meta["backend"])
            seed.append(leaf, actions)
            problems = expectations.lint(provider.expectations_dir, seeded_ok=True)
            for p in problems:
                self.out("conformance: " + p)
            self.out("%s: %d action(s) appended" % (leaf, len(actions)))
            return EXIT_USAGE if problems else EXIT_OK
        self.out(seed.format_actions(actions).rstrip("\n"))
        return EXIT_OK

    def lint(self, args: argparse.Namespace) -> int:
        problems: List[str] = []
        for name in sorted(providers.REGISTRY):
            provider = self.provider(name)
            if provider.expectations_dir.is_dir():
                problems += expectations.lint(provider.expectations_dir)
        for p in problems:
            self.out("conformance: " + p)
        self.out("conformance: lint %s" % ("clean" if not problems else "found %d problem(s)" % len(problems)))
        return EXIT_USAGE if problems else EXIT_OK

    def gate(self, args: argparse.Namespace) -> int:
        try:
            meta, cases = report.load(Path(args.results_dir))
        except (ValueError, KeyError) as e:  # ReportError included
            self.out("conformance: %s" % e)
            return EXIT_USAGE
        for line in report.summary_lines(meta, cases, Path(args.results_dir)):
            self.out(line)
        return EXIT_OK if report.gate(cases) == "green" else EXIT_RED

    def report(self, args: argparse.Namespace) -> int:
        self.out(report.markdown(Path(args.results_dir)).rstrip("\n"))
        return EXIT_OK

    def selftest(self, args: argparse.Namespace) -> int:
        suite = unittest.defaultTestLoader.discover(
            str(self.repo_root / "tests" / "conformance" / "selftest"),
            top_level_dir=str(self.repo_root / "tests"))
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        return EXIT_OK if result.wasSuccessful() else EXIT_RED

    def fingerprint(self, args: argparse.Namespace) -> int:
        self.out(self.provider(args.suite).fingerprint())
        return EXIT_OK

    def verify(self, args: argparse.Namespace) -> int:
        provider = self.provider(args.suite)
        try:
            payload.verify(provider.payload_root(), args.fingerprint or provider.fingerprint())
        except payload.PayloadError as e:
            self.out("conformance: %s" % e)
            return EXIT_RED
        self.out("%s: verified" % provider.payload_root())
        return EXIT_OK

    def build_payload(self, args: argparse.Namespace) -> int:
        try:
            self.provider(args.suite).build_payload(force=args.force)
        except (payload.PayloadError, ProviderError) as e:
            self.out("conformance: %s" % e)
            return EXIT_RED if isinstance(e, payload.PayloadError) and e.kind != "config" else EXIT_USAGE
        return EXIT_OK

    def audit(self, args: argparse.Namespace) -> int:
        provider = self.provider(args.suite)
        problems = provider.audit()
        for p in problems:
            self.out("conformance: " + p)
        if not problems:
            self.out("conformance: %s selection is consistent with upstream at the pin" % provider.name)
        return EXIT_RED if problems else EXIT_OK

    def regen(self, args: argparse.Namespace) -> int:
        provider = self.provider(args.suite)
        lines = provider.regen_selection(check=False)
        for line in lines:
            self.out("conformance: " + line)
        if not lines:
            self.out("conformance: %s generated selection is current" % provider.name)
        return EXIT_OK

    def update(self, args: argparse.Namespace) -> int:
        names = [args.suite] if getattr(args, "suite", None) else [
            n for n in sorted(providers.REGISTRY) if n != "fake"]
        codes = [update_mod.refresh(self.provider(name), getattr(args, "ref", None),
                                    args.check, self.out) for name in names]
        # An error outranks drift: an unreachable upstream has no answer.
        for rc in (update_mod.EXIT_ERROR, update_mod.EXIT_DRIFT):
            if rc in codes:
                return rc
        return EXIT_OK


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--backend", choices=BACKENDS, default=argparse.SUPPRESS,
                        help="elfuse (default), qemu, all (qemu first), or host")
    parser.add_argument("--results", default=argparse.SUPPRESS, help="results root (build/conformance)")
    parser.add_argument("--jobs", type=int, default=argparse.SUPPRESS, help="parallel batches (the reference takes one at a time)")
    parser.add_argument("--bootstrap", action="store_true", default=argparse.SUPPRESS,
                        help="record without judging; the input to seed")
    parser.add_argument("--require", action="store_true", default=argparse.SUPPRESS,
                        help="an absent prerequisite is an error, not a skip")
    parser.add_argument("--no-retry", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS,
                        help="print the selected ids and exit")
    parser.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS)


_DEFAULTS = {"backend": "elfuse", "results": "build/conformance", "jobs": 1, "bootstrap": False,
             "require": False, "no_retry": False, "dry_run": False, "verbose": False}


def build_parser(suites: List[str]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="conformance",
        description="Run upstream Linux test suites against elfuse and the QEMU reference.")
    _common(parser)
    top = parser.add_subparsers(dest="target", metavar="<suite>|lint|gate|report|selftest|update")
    top.required = True
    for name in suites:
        sp = top.add_parser(name, help="the %s suite" % name)
        sub = sp.add_subparsers(dest="command", metavar="pr|full|test|list|seed|...")
        sub.required = True
        for scope, text in (("pr", "the pull-request subset"), ("full", "everything enabled")):
            p = sub.add_parser(scope, help=text)
            _common(p)
            p.set_defaults(handler="run", scope=scope, ids=[])
        p = sub.add_parser("test", help="named tests or globs")
        p.add_argument("ids", nargs="+", metavar="ID")
        _common(p)
        p.set_defaults(handler="run", scope="test")
        p = sub.add_parser("list", help="enumerate ids")
        p.add_argument("--scope", choices=selection_mod.SCOPES, default="full")
        p.add_argument("--json", action="store_true")
        _common(p)
        p.set_defaults(handler="list_ids")
        p = sub.add_parser("seed", help="propose expectation actions from a results directory")
        p.add_argument("results_dir")
        p.add_argument("--reason")
        p.add_argument("--write", action="store_true", help="append them to the backend leaf")
        p.set_defaults(handler="seed")
        p = sub.add_parser("fingerprint", help="print the payload fingerprint")
        p.set_defaults(handler="fingerprint")
        p = sub.add_parser("verify", help="verify the staged payload")
        p.add_argument("--fingerprint")
        p.set_defaults(handler="verify")
        p = sub.add_parser("payload", help="build the payload")
        p.add_argument("--force", action="store_true")
        p.set_defaults(handler="build_payload")
        p = sub.add_parser("audit", help="check the selection against upstream at the pin")
        p.set_defaults(handler="audit")
        p = sub.add_parser("regen", help="rewrite the generated selection from the pin")
        p.set_defaults(handler="regen")
        p = sub.add_parser("update", help="refresh this suite's pins")
        p.add_argument("--check", action="store_true")
        p.add_argument("--ref", help="an upstream ref or tag instead of the latest")
        p.set_defaults(handler="update")
    p = top.add_parser("lint", help="lint every selection and expectation file")
    p.set_defaults(handler="lint")
    p = top.add_parser("gate", help="re-derive the exit code from a results directory")
    p.add_argument("results_dir")
    p.set_defaults(handler="gate")
    p = top.add_parser("report", help="markdown table over every results.json under a root")
    p.add_argument("results_dir")
    p.set_defaults(handler="report")
    p = top.add_parser("selftest", help="run the hermetic selftests")
    p.set_defaults(handler="selftest")
    p = top.add_parser("update", help="refresh every suite's pins")
    p.add_argument("--check", action="store_true")
    p.set_defaults(handler="update")
    return parser


def main(argv: Optional[List[str]] = None, repo_root: Path = REPO_ROOT,
         out: Callable[[str], None] = print) -> int:
    parser = build_parser(sorted(providers.REGISTRY))
    args = parser.parse_args(argv)
    for key, value in _DEFAULTS.items():
        if not hasattr(args, key):
            setattr(args, key, value)
    if args.target in providers.REGISTRY:
        args.suite = args.target
    cli = Cli(repo_root, out)
    try:
        return getattr(cli, args.handler)(args)
    except (ProviderError, selection_mod.SelectionError, payload.PinError, jsonc.JsoncError) as e:
        out("conformance: %s" % e)
        return EXIT_USAGE
    except NotImplementedError as e:
        out("conformance: %s" % (str(e) or "the %s suite does not support %s" % (getattr(args, "suite", "?"), args.handler)))
        return EXIT_USAGE
