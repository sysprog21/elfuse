# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from conformance import cli as cli_mod
from conformance.providers import fake as fake_mod

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "scripts" / "conformance"


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.results = Path(self.tmp.name) / "results"

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args, env=None, cwd=None):
        full = dict(os.environ)
        full.pop("CONF_REQUIRE", None)
        full.update(env or {})
        done = subprocess.run([sys.executable, str(SCRIPT)] + list(args), cwd=cwd or REPO,
                              env=full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return done.returncode, done.stdout

    def test_pr_is_green(self):
        rc, out = self.run_cli("--backend", "host", "--results", str(self.results), "fake", "pr")
        self.assertEqual(rc, 0, out)
        self.assertIn("conformance fake/host pr: 6 cases in", out)
        self.assertIn("  as_expected 4  flaked 1  filtered 1", out)
        self.assertTrue(out.rstrip().splitlines()[-1].startswith("RESULT: GREEN"))
        latest = self.results / "fake" / "host" / "latest"
        self.assertTrue((latest / "results.json").is_file())
        self.assertTrue((latest / "junit.xml").is_file())
        doc = json.loads((latest / "results.json").read_text())
        self.assertEqual(doc["gate"], "green")
        flaky = next(c for c in doc["cases"] if c["id"] == "fake:basic/flaky")
        self.assertEqual(len(flaky["attempts"]), 2)
        self.assertGreater(flaky["attempts"][0]["invocation"]["wall_us"], 0)
        self.assertTrue((latest / flaky["attempts"][0]["invocation"]["stdout"]).is_file())

    def test_full_is_red_and_gate_agrees(self):
        rc, out = self.run_cli("fake", "full", "--backend", "host", "--results", str(self.results))
        self.assertEqual(rc, 1, out)
        self.assertIn("  RED fake:slow/timeout: TIMEOUT, which no expectation can satisfy", out)
        self.assertIn("narrow or delete that matcher", out)
        latest = self.results / "fake" / "host" / "latest"
        rc, out = self.run_cli("gate", str(latest))
        self.assertEqual(rc, 1)
        self.assertIn("RESULT: RED", out)
        rc, out = self.run_cli("report", str(self.results))
        self.assertEqual(rc, 0)
        self.assertIn("| fake/host | full | red | 6 | 1 | 1 | 3 |", out)

    def test_named_tests(self):
        rc, out = self.run_cli("--backend", "host", "--results", str(self.results),
                               "fake", "test", "fake:basic/pass", "fake:basic/fa*")
        self.assertEqual(rc, 0, out)
        self.assertIn("2 cases", out)
        rc, out = self.run_cli("--backend", "host", "fake", "test", "fake:basic/pas")
        self.assertEqual(rc, 2)
        self.assertIn("no such test; near: ", out)
        rc, out = self.run_cli("--backend", "host", "fake", "test", "fake:basic/pass", "--dry-run")
        self.assertEqual((rc, out.strip()), (0, "fake:basic/pass"))

    def test_prerequisite_skip_and_require(self):
        # The copied tree lacks QEMU fixtures on every host.
        copy, run = self.repo_copy()
        rc, out = run("--backend", "qemu", "fake", "pr")
        self.assertEqual(rc, 77, out)
        self.assertIn("QEMU fixtures missing", out)
        rc, _ = run("--backend", "qemu", "--require", "fake", "pr")
        self.assertEqual(rc, 2)
        rc, _ = run("--backend", "qemu", "fake", "pr", env={"CONF_REQUIRE": "1"})
        self.assertEqual(rc, 2)

    def repo_copy(self):
        copy = Path(self.tmp.name) / "repo"
        shutil.copytree(REPO / "tests" / "conformance", copy / "tests" / "conformance",
                        ignore=shutil.ignore_patterns("__pycache__"))
        (copy / "scripts").mkdir()
        shutil.copy(SCRIPT, copy / "scripts" / "conformance")
        base = dict(os.environ)
        base.pop("CONF_REQUIRE", None)

        def run(*args, env=None):
            done = subprocess.run([sys.executable, str(copy / "scripts" / "conformance")] + list(args),
                                  cwd=copy, env=dict(base, **(env or {})), stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True)
            return done.returncode, done.stdout

        return copy, run

    def test_malformed_selection_is_a_usage_error(self):
        copy, run = self.repo_copy()
        data = copy / "tests" / "conformance" / "data" / "fake.jsonc"

        data.write_text("{ /* open")
        rc, out = run("--backend", "host", "fake", "pr")
        self.assertEqual(rc, 2, out)
        self.assertIn("unterminated block comment", out)
        self.assertNotIn("Traceback", out)

    def test_seed_round_trip(self):
        copy, run = self.repo_copy()
        rc, out = run("--backend", "host", "--results", str(self.results), "fake", "full")
        self.assertEqual(rc, 1, out)
        latest = self.results / "fake" / "host" / "latest"
        rc, out = run("fake", "seed", str(latest), "--reason", "measured on the host", "--write")
        self.assertEqual(rc, 0, out)
        self.assertIn("2 action(s) appended", out)
        leaf = copy / "tests" / "conformance" / "expectations" / "fake_host.jsonc"
        self.assertTrue(leaf.read_text().startswith("// Host expectations used by selftests."))
        rc, out = run("--backend", "host", "--results", str(self.results), "fake", "full")
        self.assertEqual(rc, 0, out)
        self.assertIn("RESULT: GREEN", out)
        rc, out = run("lint")
        self.assertEqual(rc, 0, out)
        rc, out = run("fake", "seed", str(self.results / "fake" / "host" / "latest"))
        self.assertIn("nothing to seed", out)

    def test_lint_and_selftest_entry(self):
        rc, out = self.run_cli("lint")
        self.assertEqual((rc, out.strip().splitlines()[-1]), (0, "conformance: lint clean"))
        rc, out = self.run_cli("nosuch", "pr")
        self.assertEqual(rc, 2)

    def test_gate_reports_a_truncated_results_file(self):
        (self.results).mkdir()
        (self.results / "results.json").write_text('{"run": {}}')
        rc, out = self.run_cli("gate", str(self.results))
        self.assertEqual(rc, 2, out)
        self.assertNotIn("Traceback", out)

    def test_list_on_all_backends_never_boots_the_reference(self):
        rc, out = self.run_cli("fake", "list", "--backend", "all")
        self.assertEqual(rc, 77, out)
        self.assertIn("build/elfuse", out)
        self.assertNotIn("Traceback", out)

    def test_list_reports_a_backend_error_during_enumerate(self):
        def boom(self, backend, entries):
            raise cli_mod.BackendError("guest gone")

        lines = []
        args = argparse.Namespace(suite="fake", backend="host", scope="pr", json=False, require=False)
        with unittest.mock.patch.object(fake_mod.FakeProvider, "enumerate", boom):
            rc = cli_mod.Cli(REPO, out=lines.append).list_ids(args)
        self.assertEqual((rc, lines), (cli_mod.EXIT_RED, ["conformance: backend error: guest gone"]))

    def test_update_needs_a_real_suite(self):
        rc, out = self.run_cli("fake", "update", "--check")
        self.assertEqual(rc, 2)
        self.assertIn("pins.json", out)


class UnsupportedVerbTest(unittest.TestCase):
    def test_a_provider_message_is_printed_verbatim(self):
        lines = []
        with unittest.mock.patch.object(cli_mod.Cli, "provider",
                                        lambda self, n: (_ for _ in ()).throw(NotImplementedError("fake runs nowhere"))):
            rc = cli_mod.main(["fake", "pr"], Path("."), lines.append)
        self.assertEqual(rc, 2)
        self.assertEqual(lines, ["conformance: fake runs nowhere"])
        with unittest.mock.patch.object(cli_mod.Cli, "provider",
                                        lambda self, n: (_ for _ in ()).throw(NotImplementedError())):
            lines = []
            rc = cli_mod.main(["fake", "pr"], Path("."), lines.append)
        self.assertEqual(lines, ["conformance: the fake suite does not support run"])


class UpdateExitCodeTest(unittest.TestCase):
    def fold(self, codes):
        seq = list(codes)
        args = argparse.Namespace(suite=None, ref=None, check=True)
        names = {"a": "x:A", "b": "x:B"}
        with unittest.mock.patch.dict(cli_mod.providers.REGISTRY, names, clear=True), \
                unittest.mock.patch.object(cli_mod.Cli, "provider", lambda self, n: None), \
                unittest.mock.patch.object(cli_mod.update_mod, "refresh",
                                           lambda *a, **k: seq.pop(0)):
            return cli_mod.Cli(REPO, out=lambda _: None).update(args)

    def test_an_error_outranks_drift(self):
        self.assertEqual(self.fold([0, 0]), 0)
        self.assertEqual(self.fold([0, 3]), 3)
        self.assertEqual(self.fold([3, 2]), 2)
        self.assertEqual(self.fold([2, 3]), 2)


if __name__ == "__main__":
    unittest.main()
