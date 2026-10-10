import secrets
import shlex
from unittest.mock import patch

from homelab_kit import assemble, collect, config, scaffold
from homelab_kit.neverlist import denied
from homelab_kit.platforms import MAC_COMMANDS, WINDOWS_COMMANDS, WINDOWS_PROBE
from homelab_kit.runner import CommandResult
from homelab_kit.transport import FixtureTransport, SshTransport
from tests.captured_samples import SAMPLES
from tests.support import HermeticTestCase, tree_bytes


class PlatformTests(HermeticTestCase):
    def fixture(self, system):
        root = self.root / system
        scaffold.init(root)
        scaffold.add_host(config.load(root), 'desktop', ssh='example-desktop')
        fixture = self.root / (system + '-fixture')
        fixture.mkdir()
        commands = MAC_COMMANDS if system == 'macos' else WINDOWS_COMMANDS
        entries = ['[commands]']
        import json
        for index, (name, argv) in enumerate(commands.items()):
            file = f'{index}.txt'
            (fixture / file).write_text(SAMPLES[system][name])
            entries.append(f'{json.dumps(shlex.join(argv))} = {{file = "{file}"}}')
        if system == 'windows':
            (fixture / 'probe.txt').write_text('Win32NT\n')
            (fixture / 'uname.txt').write_text('')
            entries.append(f'{json.dumps(shlex.join(WINDOWS_PROBE))} = {{file = "probe.txt"}}')
            entries.append('"uname -srm" = {file = "uname.txt", exit = 1}')
        (fixture / 'commands.toml').write_text('\n'.join(entries))
        if system == 'macos':
            hosts = fixture / 'files/etc/hosts'
            hosts.parent.mkdir(parents=True)
            hosts.write_text(SAMPLES[system]['hosts'])
        return config.load(root), FixtureTransport(fixture)

    def test_real_sanitized_samples_all_pass_and_show_os_in_index(self):
        for system, expected in [('macos', 'macOS'), ('windows', 'Windows')]:
            with self.subTest(system=system):
                lab, connection = self.fixture(system)
                code, results = collect.run(lab, factory=lambda _: connection)
                self.assertEqual(code, 0)
                self.assertEqual(results['desktop'].warnings, [])
                expected_names = MAC_COMMANDS if system == 'macos' else WINDOWS_COMMANDS
                files = tree_bytes(lab.root / 'hosts/desktop/observed')
                self.assertEqual({f'commands/{name}.txt' for name in expected_names},
                                 {name for name in files if name.startswith('commands/')})
                self.assertIn(expected, assemble.document(lab))

    def test_windows_cmd_invocation_has_no_env_or_posix_quote_prefix(self):
        connection = SshTransport('example-desktop', config.SETTINGS)
        for command in [WINDOWS_PROBE, *WINDOWS_COMMANDS.values()]:
            args = connection.argv(command)
            self.assertTrue(args[-1].startswith('powershell -NoProfile -NonInteractive -Command "'))
            self.assertTrue(args[-1].endswith('"'))
            self.fake.side_effect = None
            self.fake.return_value = CommandResult(0)
            connection.run(command)
            self.assertEqual(self.fake.call_args.kwargs['timeout'], 10)

    def test_secret_refusal_and_failure_preservation_on_both_systems(self):
        for system in ('macos', 'windows'):
            lab, connection = self.fixture(system)
            collect.run(lab, factory=lambda _: connection)
            before = tree_bytes(lab.root / 'hosts/desktop/observed')
            original = connection.run
            command = (MAC_COMMANDS if system == 'macos' else WINDOWS_COMMANDS)['services']
            value = secrets.token_urlsafe(32)
            raw = (' = '.join(('password', value)) + '\n').encode()
            with patch.object(connection, 'run', side_effect=lambda argv: CommandResult(0, raw) if argv == command else original(argv)):
                result = collect.observe(lab.hosts['desktop'], connection)
            self.assertNotIn('commands/services.txt', result.files)
            self.assertNotIn(value.encode(), b''.join(result.files.values()))
            for failure in (CommandResult(255), CommandResult(-9, timed_out=True), CommandResult(-9, too_large=True)):
                with patch.object(connection, 'run', side_effect=lambda argv: failure if argv == command else original(argv)):
                    self.assertEqual(collect.run(lab, factory=lambda _: connection)[0], 1)
                self.assertEqual(tree_bytes(lab.root / 'hosts/desktop/observed'), before)

    def test_mac_resolution_and_read_are_sh_compatible_and_bounded(self):
        connection = SshTransport('example-desktop', config.SETTINGS)
        connection.system = 'macos'
        self.fake.side_effect = None
        self.fake.return_value = CommandResult(0, b'/private/etc/hosts\n')
        self.assertEqual(connection.resolve('/etc/hosts'), '/private/etc/hosts')
        self.assertIn('/bin/sh -c', self.fake.call_args.args[0][-1])
        connection.read('/private/etc/hosts', 10)
        self.assertEqual(self.fake.call_args.kwargs['limit'], 11)

    def test_desktop_paths_are_denied_with_windows_separator_normalization(self):
        tails = ['.ssh/config', 'AppData/Local/Google/Chrome/User Data/Default/Preferences',
                 'AppData/Local/Microsoft/Edge/User Data/Default/Preferences',
                 'AppData/Roaming/Microsoft/Credentials/item', 'NTUSER.DAT', 'Library/Keychains/login.keychain']
        for tail in tails:
            path = 'C:/' + 'Users/' + 'example/' + tail
            self.assertIsNotNone(denied(path))
            self.assertIsNotNone(denied(path.replace('/', '\\')))
        self.assertIsNotNone(denied('C:/Windows/System32/config/SAM'))
        self.assertIsNotNone(denied('%USERPROFILE%/.ssh/config'))

    def test_mac_builtin_hosts_resolved_denylist_and_windows_custom_paths(self):
        for system in ('macos', 'windows'):
            lab, connection = self.fixture(system)
            lab.hosts['desktop'].data['files'] = ['/etc/sample.conf']
            if system == 'macos':
                connection.config['links'] = {'/etc/hosts': '/etc/shadow'}
            result = collect.observe(lab.hosts['desktop'], connection)
            self.assertFalse(any(call[0] == 'read' for call in connection.calls))
            self.assertTrue(result.warnings)
