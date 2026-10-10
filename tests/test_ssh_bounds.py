"""Real short-lived fake SSH processes exercise prompts, hangs and budgets."""
import io
import subprocess
import sys
import time
from unittest.mock import MagicMock, patch

from homelab_kit import collect, config, runner, scaffold, transport
from tests.support import HermeticTestCase, tree_bytes
from tests.test_collect import FakeTransport


class SshBoundsTests(HermeticTestCase):
    def fake_ssh(self, script, settings=None):
        path = self.root / 'fake_ssh.py'
        path.write_text(script)
        connection = transport.SshTransport('example-target', settings or dict(
            config.SETTINGS, command_timeout_seconds=0.15))
        original = connection.argv
        connection.argv = lambda action: [sys.executable, str(path), *original(action)[1:]]
        return connection

    def test_fake_ssh_checks_options_and_eof_instead_of_prompting(self):
        connection = self.fake_ssh('''import sys
args = sys.argv[1:]
for option in ['BatchMode=yes', 'NumberOfPasswordPrompts=0', 'StrictHostKeyChecking=yes', 'ConnectTimeout=10']:
    assert option in args
assert not any('ControlMaster' in a or 'ControlPath' in a for a in args)
assert sys.stdin.read() == ''
print('Linux example')
''', dict(config.SETTINGS, command_timeout_seconds=2))
        with patch.object(runner, 'run', wraps=REAL_RUN):
            self.assertEqual(connection.run(['uname']).code, 0)

    def test_fake_ssh_that_prompts_and_hangs_finishes_in_seconds(self):
        connection = self.fake_ssh("import time; print('Password: ', flush=True); time.sleep(30)")
        started = time.monotonic()
        with patch.object(runner, 'run', wraps=REAL_RUN):
            result = connection.run(['uname'])
        self.assertTrue(result.timed_out)
        self.assertIn('unreachable/timeout', transport.failure_reason(result))
        self.assertLess(time.monotonic() - started, 3)

    def test_fake_ssh_denial_and_unknown_key_have_plain_fixes(self):
        for raw, expected in [('Permission denied (publickey).', 'authentication failed (publickey)'),
                              ('Host key verification failed.', 'first connection: trust the host key with ssh HOST true once'),
                              (' '.join(('No ED25519 host', 'key', 'is known for example-target and you have requested strict checking.')), 'host key unverified')]:
            connection = self.fake_ssh('import sys; sys.stderr.write(' + repr(raw) + '); sys.exit(255)',
                                       dict(config.SETTINGS, command_timeout_seconds=2))
            with patch.object(runner, 'run', wraps=REAL_RUN):
                result = connection.run(['uname'])
            self.assertIn(expected, transport.failure_reason(result))

    def test_hanging_ssh_read_uses_same_deadline(self):
        connection = self.fake_ssh('import time; time.sleep(30)')
        started = time.monotonic()
        with patch.object(runner, 'run', wraps=REAL_RUN), self.assertRaises(transport.CaptureFailure) as caught:
            connection.read('/etc/example.conf', 10)
        self.assertIn('unreachable/timeout', caught.exception.reason)
        self.assertLess(time.monotonic() - started, 3)

    def test_host_budget_bounds_later_commands_and_reads(self):
        connection = transport.SshTransport('example-target', dict(config.SETTINGS, host_timeout_seconds=1))
        self.fake.side_effect = None
        self.fake.return_value = runner.CommandResult(0, b'abc')
        with patch('homelab_kit.transport.time.monotonic', side_effect=[10, 10, 10.8, 11.1]):
            connection.run(['uname'])
            self.assertEqual(self.fake.call_args.kwargs['timeout'], 1)
            connection.read('/etc/example.conf', 10)
            self.assertAlmostEqual(self.fake.call_args.kwargs['timeout'], 0.2)
            with self.assertRaisesRegex(transport.CaptureFailure, 'Connection lost'):
                connection.run(['hostname'])
        self.assertEqual(self.fake.call_count, 2)

    def test_budget_failure_preserves_capture_and_next_host_runs(self):
        root = self.root / 'lab'
        scaffold.init(root)
        for name in ('example-first', 'example-next'):
            scaffold.add_host(config.load(root), name, ssh='example-target')
        lab = config.load(root)
        collect.run(lab, factory=lambda _: FakeTransport())
        before = tree_bytes(root / 'hosts/example-first/observed')
        expired = transport.SshTransport('example-target', dict(config.SETTINGS, host_timeout_seconds=0))
        code, results = collect.run(lab, factory=lambda host: expired if host.name == 'example-first' else FakeTransport())
        self.assertEqual(code, 1)
        self.assertIn('total wall-clock budget', results['example-first'].warnings[0])
        self.assertIn('previous capture retained', results['example-first'].warnings[0])
        self.assertEqual(tree_bytes(root / 'hosts/example-first/observed'), before)
        self.assertEqual(results['example-next'].code, 0)

    def test_connect_timeout_is_positive_and_never_exceeds_ten(self):
        for value, expected in [(0, 1), (3, 3), (120, 10)]:
            args = transport.SshTransport('example-target', dict(config.SETTINGS, connect_timeout_seconds=value)).argv(['uname'])
            self.assertIn('ConnectTimeout=' + str(expected), args)
            self.assertFalse(any('ControlMaster' in a or 'ControlPath' in a for a in args))

    def test_local_commands_share_the_host_budget(self):
        connection = transport.LocalTransport(dict(config.SETTINGS, host_timeout_seconds=0))
        with self.assertRaises(transport.CaptureFailure):
            connection.run(['uname'])
        self.fake.assert_not_called()

    def test_timeout_kills_child_holding_inherited_pipes(self):
        marker = self.root / 'child-survived'
        child = "import time; from pathlib import Path; time.sleep(0.8); Path(" + repr(str(marker)) + ").touch(); time.sleep(30)"
        parent = 'import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",' + repr(child) + ']); time.sleep(30)'
        started = time.monotonic()
        result = REAL_RUN([sys.executable, '-c', parent], timeout=0.15)
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started, 3)
        time.sleep(0.9)
        self.assertFalse(marker.exists(), 'Descendant survived the timeout')

    def test_exited_parent_leaves_no_child_holding_pipes(self):
        marker = self.root / 'orphan-survived'
        child = "import time; from pathlib import Path; time.sleep(0.8); Path(" + repr(str(marker)) + ").touch(); time.sleep(30)"
        parent = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c",' + repr(child) + '])'
        started = time.monotonic()
        result = REAL_RUN([sys.executable, '-c', parent], timeout=0.15)
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started, 3)
        time.sleep(0.9)
        self.assertFalse(marker.exists(), 'Orphaned descendant survived the timeout')

    def test_windows_tree_termination_is_bounded_and_noninteractive(self):
        process = MagicMock(pid=12345)
        with patch('homelab_kit.runner.os.name', 'nt'), patch('homelab_kit.runner.subprocess.run') as kill:
            runner.kill_tree(process)
        kill.assert_called_once_with(['taskkill', '/PID', '12345', '/T', '/F'],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, timeout=2, check=False)
        process.kill.assert_called_once()

    def test_windows_spawn_failure_closes_all_pipe_ends(self):
        streams = [io.BytesIO() for _ in range(4)]
        with patch('homelab_kit.runner.os.name', 'nt'), patch.object(runner, 'windows_pipe', side_effect=[tuple(streams[:2]), tuple(streams[2:])]), patch('homelab_kit.runner.subprocess.Popen', side_effect=FileNotFoundError):
            result = REAL_RUN(['example-missing-ssh'])
        self.assertTrue(result.missing_executable)
        self.assertTrue(all(stream.closed for stream in streams))

    def test_zero_timeout_launches_nothing(self):
        with patch('homelab_kit.runner.subprocess.Popen') as spawn:
            self.assertTrue(REAL_RUN(['example-ssh'], timeout=0).timed_out)
        spawn.assert_not_called()

    def test_parent_can_close_pipes_without_escaping_deadline(self):
        script = 'import os,time; os.close(1); os.close(2); time.sleep(30)'
        started = time.monotonic()
        result = REAL_RUN([sys.executable, '-c', script], timeout=0.15)
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started, 3)


REAL_RUN = runner.run
