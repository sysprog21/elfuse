# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
# Alpine's initramfs has no sftp-server, so files return through ssh cat.

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from conformance.backends import base, proc
from conformance.model import Invocation

SENTINEL = "__CONF_RC="
DIR_MARK = " __CONF_DIR="
TRANSPORT_SLACK_S = 15


class SshSession:
    def __init__(self, port: int, key: Path, host: str = "127.0.0.1", user: str = "root",
                 ssh: str = "ssh"):
        self.port, self.key, self.host, self.user = port, key, host, user
        self.ssh = ssh

    def options(self) -> List[str]:
        # The shell lanes spell the same list in tests/lib/qemu-ssh.sh.
        return [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=6",
            "-i", str(self.key),
        ]

    def ssh_argv(self, script: str) -> List[str]:
        return [self.ssh] + self.options() + ["-p", str(self.port),
                                              "%s@%s" % (self.user, self.host), script]

    @staticmethod
    def remote_script(argv: List[str], timeout_s: int, env: Dict[str, str],
                      cwd: Optional[str], cleanup: bool = False) -> str:
        """Build the guest command with an isolated cwd and fixed environment."""
        exports = "export %s;" % " ".join('%s="$PWD"' % n for n in base.SCRATCH_NAMES) + "".join(
            " export %s=%s;" % (k, shlex.quote(v)) for k, v in sorted({**base.FIXED_ENV, **env}.items()))
        enter = "cd %s" % shlex.quote(cwd) if cwd else 'd=$(mktemp -d /tmp/conf.XXXXXX) && cd "$d"'
        if cleanup:
            enter += " && trap 'cd / && rm -rf \"$d\"' EXIT"
        return (
            "%s && { %s /usr/bin/timeout -s KILL %d %s; rc=$?; "
            'printf "\\n%s%%s%s%%s\\n" "$rc" "$PWD"; }'
            % (enter, exports, timeout_s, shlex.join(argv), SENTINEL, DIR_MARK)
        )

    @staticmethod
    def parse_sentinel(text: str) -> Optional[tuple]:
        # DIR_MARK terminates rc and detects a partial sentinel write.
        for line in reversed(text.splitlines()):
            if line.startswith(SENTINEL):
                head, mark, tail = line.partition(DIR_MARK)
                field = head[len(SENTINEL):].split()
                if not mark or not field or not field[0].lstrip("-").isdigit():
                    return None
                return int(field[0]), tail
        return None

    def run(self, argv: List[str], timeout_s: int, scratch: Path,
            env: Optional[Dict[str, str]] = None, cwd: Optional[str] = None,
            fetch: Iterable[str] = ()) -> Invocation:
        cleanup = not cwd and not fetch
        script = self.remote_script(argv, timeout_s, env or {}, cwd, cleanup)
        inv = proc.run_local(self.ssh_argv(script), timeout_s + TRANSPORT_SLACK_S, scratch,
                             stdout_name="stdout.raw")
        raw_path, out_path = Path(inv.stdout), scratch / "stdout"
        raw = raw_path.read_bytes()
        parsed = self.parse_sentinel(raw.decode("utf-8", "replace"))
        # A clean ssh exit vouches for the sentinel; a lost tail can leave a
        # guest-printed lookalike as the last line.
        if parsed is None or inv.execution != "normal" or inv.exit_code != 0:
            raw_path.replace(out_path)
            # An uninterruptible guest can outlive both timeout and SIGKILL.
            return Invocation(execution="timeout" if inv.execution == "timeout" else "transport",
                              wall_us=inv.wall_us,
                              stdout=str(out_path), stderr=inv.stderr)
        rc, guest_dir = parsed
        os.truncate(raw_path, max(raw.rfind(SENTINEL.encode()) - 1, 0))
        raw_path.replace(out_path)
        if guest_dir:
            lost = [name for name in fetch
                    if not self.copy_from("%s/%s" % (guest_dir, name), scratch / name)]
            if not cwd and fetch:
                proc.run_local(self.ssh_argv("rm -rf %s" % shlex.quote(guest_dir)), 30,
                               scratch / ".cleanup")
            if lost:
                return Invocation(execution="transport", wall_us=inv.wall_us,
                                  stdout=str(out_path), stderr=inv.stderr)
        timed_out = rc == 137 and inv.wall_us >= timeout_s * 1_000_000
        # The shell status cannot distinguish signal death from exit(128+n).
        return proc.classify(rc, timed_out, inv.wall_us, str(out_path), inv.stderr)

    def copy_from(self, remote: str, local: Path) -> bool:
        inv = proc.run_local(self.ssh_argv("cat %s" % shlex.quote(remote)), 120,
                             local.parent / ".fetch", stdout_name=local.name + ".part")
        if inv.exit_code != 0:
            return False
        Path(inv.stdout).replace(local)
        return True
