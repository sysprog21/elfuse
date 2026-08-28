# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import os
import stat
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

from conformance.backends import BackendError, elfuse, proc, qemu, ssh


def script(path, body):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class ProcTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_normal(self):
        inv = proc.run_local(["sh", "-c", "echo out; echo err >&2; exit 3"], 10, self.dir)
        self.assertEqual((inv.execution, inv.exit_code, inv.signal), ("normal", 3, None))
        self.assertEqual(Path(inv.stdout).read_text(), "out\n")
        self.assertEqual(Path(inv.stderr).read_text(), "err\n")
        self.assertGreater(inv.wall_us, 0)

    def test_unspawnable(self):
        inv = proc.run_local([str(self.dir / "absent")], 10, self.dir)
        self.assertEqual(inv.execution, "transport")
        self.assertIn("cannot spawn", Path(inv.stderr).read_text())

    def test_signal(self):
        inv = proc.run_local(["sh", "-c", "kill -SEGV $$"], 10, self.dir)
        self.assertEqual((inv.execution, inv.exit_code, inv.signal), ("signal", None, 11))

    def test_timeout_kills_the_group(self):
        started = time.monotonic()
        inv = proc.run_local(["sh", "-c", "sleep 30 & echo $! > pid; wait"], 1, self.dir)
        self.assertEqual(inv.execution, "timeout")
        self.assertLess(time.monotonic() - started, 5)
        self.assertIsNone(inv.exit_code)
        child = int((self.dir / "pid").read_text())
        for _ in range(50):  # SIGKILL reaches the orphan asynchronously
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            self.fail("background child %d survived the group kill" % child)


class SshTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.args = self.dir / "args"
        self.stub = script(
            self.dir / "ssh",
            'printf "%%s\\n" "$@" >> "%s"\n' % self.args
            + 'case "$*" in *"cat /tmp/conf.abc/result.xml") printf "<xml/>"; exit 0 ;; esac\n'
            + 'case "$*" in *"rm -rf /tmp/conf"*) exit 0 ;; esac\n'
            + 'case "$STUB" in\n'
            '  ok) printf "hello\\n\\n__CONF_RC=3 __CONF_DIR=/tmp/conf.abc\\n"; exit 3 ;;\n'
            '  sig) printf "__CONF_RC=139 __CONF_DIR=/tmp/x\\n"; exit 139 ;;\n'
            "  lost) exit 255 ;;\n"
            "esac\n",
        )
        self.session = ssh.SshSession(2222, Path("/k"), ssh=str(self.stub))

    def tearDown(self):
        self.tmp.cleanup()

    def run_stub(self, mode, **kw):
        os.environ["STUB"] = mode
        try:
            return self.session.run(["true", "a b"], 5, self.dir / mode, **kw)
        finally:
            del os.environ["STUB"]

    def test_script(self):
        text = ssh.SshSession.remote_script(["cmd", "a b"], 7, {"X": "y z"}, None)
        self.assertIn("mktemp -d /tmp/conf.XXXXXX", text)
        self.assertNotIn("rm -rf", text)
        self.assertIn("export LC_ALL=C;", text)
        self.assertIn("trap 'cd / && rm -rf \"$d\"' EXIT", ssh.SshSession.remote_script(["x"], 1, {}, None, cleanup=True))
        self.assertIn("/usr/bin/timeout -s KILL 7 cmd 'a b'", text)
        self.assertIn("export X='y z';", text)
        self.assertIn('export HOME="$PWD"', text)
        self.assertIn(ssh.SENTINEL, text)
        self.assertIn("cd /opt/ltp", ssh.SshSession.remote_script(["x"], 1, {}, "/opt/ltp"))

    def test_ok(self):
        inv = self.run_stub("ok", fetch=["result.xml"])
        self.assertEqual((inv.execution, inv.exit_code), ("normal", 3))
        self.assertEqual(Path(inv.stdout).read_text(), "hello\n")
        args = self.args.read_text().splitlines()
        self.assertIn("BatchMode=yes", args)
        self.assertEqual(args[args.index("-p") + 1], "2222")
        self.assertEqual(args[-2], "root@127.0.0.1")
        self.assertEqual((self.dir / "ok" / "result.xml").read_text(), "<xml/>")
        self.assertIn("rm -rf /tmp/conf.abc", self.args.read_text())

    def test_signal(self):
        inv = self.run_stub("sig")
        self.assertEqual((inv.execution, inv.signal), ("signal", 11))

    def test_a_sentinel_cut_mid_write_is_a_transport_loss(self):
        self.assertIsNone(ssh.SshSession.parse_sentinel("x\n" + ssh.SENTINEL + "1"))
        self.assertEqual(ssh.SshSession.parse_sentinel(ssh.SENTINEL + "12" + ssh.DIR_MARK + "/t"), (12, "/t"))

    def test_a_garbled_sentinel_is_a_transport_loss(self):
        # A partial sentinel is a transport loss, not a parser error.
        for line in ("__CONF_RC=", "__CONF_RC=xx __CONF_DIR=/tmp/a", "__CONF_RC=-"):
            self.assertIsNone(ssh.SshSession.parse_sentinel(line), line)
        self.assertEqual(ssh.SshSession.parse_sentinel("__CONF_RC=3 __CONF_DIR=/tmp/a b"),
                         (3, "/tmp/a b"))

    def test_transport(self):
        inv = self.run_stub("lost")
        self.assertEqual(inv.execution, "transport")
        self.assertIsNone(inv.exit_code)


class ElfuseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_argv_and_prerequisites(self):
        b = elfuse.ElfuseBackend(self.dir, sysroot=self.dir / "root")
        self.assertIn("absent; run: make", b.prerequisites())
        script(self.dir / "elfuse", "exit 0\n")
        (self.dir / "build").mkdir()
        os.rename(self.dir / "elfuse", self.dir / "build" / "elfuse")
        self.assertIn("sysroot", b.prerequisites())
        (self.dir / "root").mkdir()
        self.assertIsNone(b.prerequisites())
        self.assertEqual(
            b.argv(["/bin/true", "x"]),
            [str(self.dir / "build" / "elfuse"), "--timeout", "0", "--sysroot",
             str(self.dir / "root"), "/bin/true", "x"],
        )

    def test_run_scrubs_the_environment(self):
        (self.dir / "build").mkdir()
        script(self.dir / "build" / "elfuse", 'shift 2; echo "$TZ $HOME"; exec "$@"\n')
        b = elfuse.ElfuseBackend(self.dir)
        with unittest.mock.patch.dict(os.environ, {"LEAK": "1"}):
            inv = b.run(["sh", "-c", 'echo "${LEAK:-clean}"'], 5, self.dir / "s")
        self.assertEqual(inv.exit_code, 0)
        self.assertEqual(Path(inv.stdout).read_text(), "UTC %s\nclean\n" % (self.dir / "s"))

    def test_orphan_pids(self):
        listing = ("  12   1 40 /repo/build/elfuse --fork-child 8\n"
                   "  13 500 40 /repo/build/elfuse --fork-child 8\n"
                   "  14   1 40 /repo/build/elfuse --timeout 0 /bin/true\n"
                   "  15   1 40 /other/build/elfuse --fork-child 8\n"
                   "  16   1 41 /repo/build/elfuse --fork-child 9\n")
        self.assertEqual(elfuse.orphan_pids(listing, "/repo/build/elfuse", 40), [12])

    def test_serialize_excludes_a_second_session(self):
        a, b = elfuse.ElfuseBackend(self.dir), elfuse.ElfuseBackend(self.dir)
        a.lock_file = b.lock_file = self.dir / "lock"
        with a.serialize():
            with self.assertRaises(BackendError):
                with b.serialize():
                    pass
        with b.serialize():
            pass


class QemuTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_prerequisites_report_the_tree_before_the_host(self):
        # Missing fixtures produce the same answer on every host.
        b = qemu.QemuBackend(self.dir)
        with unittest.mock.patch("shutil.which", return_value=None):
            self.assertIn("QEMU fixtures missing", b.prerequisites())

    def test_guest_path(self):
        b = qemu.QemuBackend(self.dir)
        (self.dir / "tests").mkdir()
        self.assertEqual(b.guest_path(self.dir / "tests" / "x"), "/mnt/host/tests/x")
        with self.assertRaises(BackendError):
            b.guest_path(Path("/etc/passwd"))

    def test_start_reads_the_state_file(self):
        runner = script(
            self.dir / "runner.sh",
            '[ "$1" = start ] && printf "port=2200\\nkey=/k\\npidfile=/p\\n" > "$3"\n'
            'echo "$QEMU_MEM $QEMU_BOOT_TIMEOUT" > "%s/mem"\n' % self.dir,
        )
        b = qemu.QemuBackend(self.dir, mem_mib=4096, runner=runner, state_dir=self.dir)
        with unittest.mock.patch.dict(os.environ, {"QEMU_BOOT_TIMEOUT": "300", "QEMU_MEM": "1"}):
            b.start()
        self.assertEqual((b.session.port, b.session.key), (2200, Path("/k")))
        self.assertEqual((self.dir / "mem").read_text().split(), ["4096", "300"])
        b.stop()
        self.assertIsNone(b.session)

    def test_start_without_state_is_an_error(self):
        runner = script(self.dir / "runner.sh", "exit 0\n")
        b = qemu.QemuBackend(self.dir, runner=runner, state_dir=self.dir)
        with self.assertRaises(BackendError):
            b.start()

    def test_start_reaps_the_vm_a_stale_state_file_names(self):
        runner = script(
            self.dir / "runner.sh",
            'echo "$1" >> "%s/verbs"\n' % self.dir +
            '[ "$1" = start ] && printf "port=2200\\nkey=/k\\n" > "$3"\nexit 0\n',
        )
        (self.dir / "qemu.state").write_text("port=2199\nkey=/k\npidfile=/p\n")
        b = qemu.QemuBackend(self.dir, runner=runner, state_dir=self.dir)
        b.start()
        self.assertEqual((self.dir / "verbs").read_text().split(), ["stop", "start"])
        self.assertEqual(b.session.port, 2200)

    def test_start_after_a_bad_state_stops_the_vm(self):
        for state in ("key=/k\n", "port=abc\nkey=/k\n"):
            runner = script(
                self.dir / "runner.sh",
                'echo "$1" >> "%s/verbs"\n' % self.dir +
                '[ "$1" = stop ] && rm -f "$3"\n'
                '[ "$1" = start ] && printf "%s" > "$3"\nexit 0\n' % state,
            )
            b = qemu.QemuBackend(self.dir, runner=runner, state_dir=self.dir)
            with self.assertRaises(BackendError):
                b.start()
            self.assertEqual((self.dir / "verbs").read_text().split(), ["start", "stop"])
            (self.dir / "verbs").unlink()

    def test_a_failed_stop_is_an_error(self):
        runner = script(
            self.dir / "runner.sh",
            '[ "$1" = start ] && printf "port=2200\\nkey=/k\\n" > "$3"\n'
            '[ "$1" = stop ] && { echo "no such vm"; exit 1; }\nexit 0\n',
        )
        b = qemu.QemuBackend(self.dir, runner=runner, state_dir=self.dir)
        b.start()
        with self.assertRaises(BackendError) as cm:
            b.stop()
        self.assertIn("no such vm", str(cm.exception))

    def test_a_relative_scratch_still_names_an_absolute_home(self):
        env = elfuse.base.guest_environment("rel/x")
        self.assertTrue(Path(env["HOME"]).is_absolute())
        self.assertEqual(env["HOME"], env["TMPDIR"])

    def test_serialize_excludes_a_second_session_on_the_state_dir(self):
        a = qemu.QemuBackend(self.dir, state_dir=self.dir)
        b = qemu.QemuBackend(self.dir, state_dir=self.dir)
        with a.serialize():
            with self.assertRaises(BackendError):
                with b.serialize():
                    pass

    def test_start_after_an_unreadable_state_stops_the_vm(self):
        runner = script(
            self.dir / "runner.sh",
            'echo "$1" >> "%s/verbs"\n' % self.dir +
            '[ "$1" = stop ] && rm -rf "$3"\n'
            '[ "$1" = start ] && mkdir "$3"\nexit 0\n',
        )
        b = qemu.QemuBackend(self.dir, runner=runner, state_dir=self.dir)
        with self.assertRaises(BackendError):
            b.start()
        self.assertEqual((self.dir / "verbs").read_text().split(), ["start", "stop"])


if __name__ == "__main__":
    unittest.main()
