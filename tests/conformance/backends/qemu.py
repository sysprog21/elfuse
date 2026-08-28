# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from conformance.backends import base
from conformance.backends.ssh import SshSession
from conformance.model import Invocation

FIXTURES = ("kernel/vmlinuz-virt", "initramfs.cpio.gz", "keys/ssh_key")

RUNNER_TIMEOUT_S = 600
KILL_WAIT_S = 30
# Match the environment passed to qemu-runner.sh.
RUNNER_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"


def parse_state(text: str) -> Dict[str, str]:
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip()] = value.strip()
    return out


class QemuBackend(base.Backend):
    name = "qemu"
    max_jobs = 1  # the reference takes one case at a time

    def __init__(self, repo_root: Path, mem_mib: int = 2048,
                 runner: Optional[Path] = None, state_dir: Optional[Path] = None):
        self.repo_root = repo_root
        self.mem_mib = mem_mib
        self.runner = runner or repo_root / "tests" / "qemu-runner.sh"
        self.state_file = (state_dir or repo_root / "build" / "conformance") / "qemu.state"
        # One session per checkout: start() reaps whatever the state file names.
        self.lock_file = self.state_file.with_suffix(".lock")
        self.session: Optional[SshSession] = None

    def prerequisites(self) -> Optional[str]:
        fixtures = self.repo_root / "externals" / "test-fixtures"
        missing = [f for f in FIXTURES if not (fixtures / f).is_file()]
        if missing:
            return "QEMU fixtures missing (%s); run: bash tests/fetch-fixtures.sh" % ", ".join(missing)
        if shutil.which("qemu-system-aarch64", path=RUNNER_PATH) is None:
            return ("qemu-system-aarch64 is not on the runner PATH (%s); "
                    "run: brew install qemu" % RUNNER_PATH)
        return None

    def _runner(self, verb: str) -> subprocess.CompletedProcess:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with subprocess.Popen(
            ["bash", str(self.runner), verb, "--state-file", str(self.state_file)],
            cwd=str(self.repo_root),
            env={**{k: v for k, v in os.environ.items() if k.startswith("QEMU_") or k == "TMPDIR"},
                 "PATH": RUNNER_PATH, "QEMU_MEM": str(self.mem_mib), "HOME": str(Path.home())},
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        ) as run:
            try:
                out, _ = run.communicate(timeout=RUNNER_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                # SIGTERM, not SIGKILL, so the runner's EXIT trap reaps the VM.
                run.terminate()
                run.communicate(timeout=KILL_WAIT_S)
                raise base.BackendError("qemu-runner %s did not return in %ds" % (verb, RUNNER_TIMEOUT_S)) from None
        return subprocess.CompletedProcess(run.args, run.returncode, out)

    def start(self) -> None:
        # A state file from an interrupted run names a VM still up; reap it
        # first or this start would overwrite the only record of it.
        self.stop()
        done = self._runner("start")
        if done.returncode != 0:
            raise base.BackendError("qemu-runner start failed:\n%s" % done.stdout)
        try:
            state = parse_state(self.state_file.read_text()) if self.state_file.exists() else {}
            if "port" not in state or "key" not in state:
                raise base.BackendError("qemu-runner wrote no port/key to %s" % self.state_file)
            self.session = SshSession(int(state["port"]), Path(state["key"]))
        except (base.BackendError, ValueError, OSError) as e:
            self.stop()
            raise base.BackendError(str(e)) from None

    def stop(self) -> None:
        if self.session is not None or self.state_file.exists():
            done = self._runner("stop")
            if done.returncode != 0:
                raise base.BackendError("qemu-runner stop failed:\n%s" % done.stdout)
            self.session = None

    def guest_path(self, host_path: Path) -> str:
        try:
            rel = Path(host_path).resolve().relative_to(self.repo_root.resolve())
        except ValueError:
            raise base.BackendError(
                "%s is outside the repo root, unreachable over the 9p share" % host_path
            ) from None
        return "/mnt/host/%s" % rel.as_posix()

    def run(
        self,
        argv: List[str],
        timeout_s: int,
        scratch: Path,
        env: Optional[Dict[str, str]] = None,
        fetch: Iterable[str] = (),
    ) -> Invocation:
        if self.session is None:
            raise base.BackendError("qemu backend is not started")
        return self.session.run(argv, timeout_s, scratch, env=env, fetch=fetch)
