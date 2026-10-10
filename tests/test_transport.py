import shlex
import subprocess
import sys
import time
from unittest.mock import MagicMock, patch

from homelab_kit.errors import ConfigError
from homelab_kit.runner import CommandResult, read_pipes
from homelab_kit.runner import run as bounded_run
from homelab_kit.transport import FixtureTransport, LocalTransport, SshTransport
from tests.support import HermeticTestCase

SETTINGS = {"connect_timeout_seconds": 10, "command_timeout_seconds": 30, "max_output_bytes": 1048576}


class TransportTests(HermeticTestCase):
    def test_windows_pipe_reader_caps_real_output_and_times_out(self) -> None:
        for script, limit, timeout, expected in (
            ('print("x" * 200000)', 100, 2, (False, True)),
            ('import time; time.sleep(2)', 100, 0.05, (True, False)),
            ('print("ok")', 100, 2, (False, False)),
        ):
            process = subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                buffers = {'stdout': bytearray(), 'stderr': bytearray()}
                self.assertEqual(read_pipes(process, buffers, time.monotonic() + timeout, limit), expected)
                self.assertLessEqual(len(buffers['stdout']), limit + 1)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
                process.stdout.close()
                process.stderr.close()

    def test_runner_caps_output_without_starting_a_process(self) -> None:
        process = MagicMock()
        process.returncode = -9
        selector = MagicMock()
        selector.get_map.return_value = {'stdout': object()}
        key = MagicMock()
        key.data = 'stdout'
        selector.select.return_value = [(key, 1)]
        with patch('homelab_kit.runner.os.killpg'), patch('homelab_kit.runner.subprocess.Popen', return_value=process), patch('homelab_kit.runner.selectors.DefaultSelector') as factory, patch('homelab_kit.runner.os.read', return_value=b'x' * 65536):
            factory.return_value.__enter__.return_value = selector
            result = bounded_run(['example-reader'], limit=100)
        self.assertTrue(result.too_large)
        self.assertEqual(len(result.stdout), 101)
        process.kill.assert_called_once()

    def test_runner_timeout_kills_and_reaps_fake_process(self) -> None:
        process = MagicMock()
        process.returncode = -9
        with patch('homelab_kit.runner.os.killpg'), patch('homelab_kit.runner.subprocess.Popen', return_value=process), patch('homelab_kit.runner.selectors.DefaultSelector'), patch('homelab_kit.runner.time.monotonic', side_effect=[0, 2, 3]):
            result = bounded_run(['example-reader'], timeout=1)
        self.assertTrue(result.timed_out)
        process.kill.assert_called_once()
        process.wait.assert_called_once()

    def test_file_read_has_room_for_overflow_sentinel(self) -> None:
        self.fake.side_effect = None
        self.fake.return_value = CommandResult(0, b"abc")
        self.assertEqual(SshTransport("maple", SETTINGS).read("/etc/example.conf", 2), b"abc")
        self.assertEqual(self.fake.call_args.kwargs["limit"], 3)

    def test_exact_ssh_and_quoting(self) -> None:
        self.fake.side_effect = None
        self.fake.return_value = CommandResult(0, b"ok")
        connection = SshTransport("maple", SETTINGS)
        args = ["cat", "/etc/awkward ' name;value"]
        connection.run(args)
        expected = ["ssh", "-T", "-a", "-x", "-o", "BatchMode=yes", "-o", "NumberOfPasswordPrompts=0", "-o", "StrictHostKeyChecking=yes", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10", "--", "maple", shlex.join(["env", "LC_ALL=C", *args])]
        self.fake.assert_called_once_with(expected, timeout=30, limit=1048576)
        self.assertEqual(connection.describe(args), shlex.join(expected))

    def test_alias_and_timeout(self) -> None:
        for alias in ("-bad", "two words", "a\ncat"):
            with self.assertRaises(ConfigError):
                SshTransport(alias, SETTINGS)
        self.fake.side_effect = None
        self.fake.return_value = CommandResult(-9, timed_out=True)
        self.assertTrue(SshTransport("maple", SETTINGS).run(["hostname"]).timed_out)

    def test_fixture_unknown_and_link(self) -> None:
        (self.root / "commands.toml").write_text('[links]\n"/etc/example.conf" = "/etc/shadow"\n')
        connection = FixtureTransport(self.root)
        self.assertEqual(connection.run(["unknown"]).code, 127)
        self.assertEqual(connection.resolve("/etc/example.conf"), "/etc/shadow")
        self.assertEqual(connection.calls, [("run", ("unknown",)), ("resolve", "/etc/example.conf")])

    def test_direct_file_reads_only_in_temp(self) -> None:
        path = self.root / "sample"
        path.write_bytes(b"abcdef")
        connection = LocalTransport(SETTINGS)
        with patch("homelab_kit.runner.run", wraps=bounded_run):
            self.assertEqual(connection.read(str(path), 2), b"abc")
        self.assertEqual(connection.resolve(str(path)), str(path))
        self.assertEqual(connection.glob(str(self.root), "sam*"), [str(path)])
