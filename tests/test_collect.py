import secrets
from unittest.mock import patch

from homelab_kit import assemble, collect, config, scaffold, transport
from homelab_kit.errors import ConfigError
from homelab_kit.runner import CommandResult
from tests.support import HermeticTestCase, tree_bytes


class FakeTransport:
    def __init__(self, output=b'example output\n', files=None, links=None):
        self.output, self.files, self.links = output, files or {}, links or {}
        self.calls = []
        self.fail = False

    def describe(self, action):
        return 'fake: ' + ' '.join(action)

    def run(self, argv):
        self.calls.append(('run', tuple(argv)))
        output = b'Linux 6.1.0 x86_64\n' if argv[0] == 'uname' else self.output
        return CommandResult(255 if self.fail else 0, output, secrets.token_bytes(20))

    def resolve(self, path):
        self.calls.append(('resolve', path))
        return self.links.get(path, path if path in self.files else None)

    def read(self, path, limit):
        self.calls.append(('read', path))
        return self.files[path][:limit + 1]

    def glob(self, directory, pattern):
        raise AssertionError('No glob collection')


class CollectionTests(HermeticTestCase):
    def lab(self, paths=None):
        root = self.root / 'lab'
        scaffold.init(root)
        scaffold.add_host(config.load(root), 'compute', ssh='operator@192.0.2.10', files=paths)
        return config.load(root)

    def test_five_mixed_hosts_all_selected_local_and_docs_handling(self):
        lab = self.lab()
        scaffold.add_host(lab, 'backup', ssh='backup-alias', role='Backup', ip='192.0.2.11')
        scaffold.add_host(config.load(lab.root), 'workstation', direct=True)
        scaffold.add_host(config.load(lab.root), 'storage', role='NAS', config_export='Encrypted offline storage: export folder')
        scaffold.add_host(config.load(lab.root), 'router', role='Router')
        lab = config.load(lab.root)
        ssh = {name: FakeTransport() for name in ('compute', 'backup')}
        local = transport.LocalTransport(config.SETTINGS)
        requested = []
        def factory(host):
            requested.append(host.name)
            return local if host.kind == 'local' else ssh[host.name]
        self.fake.side_effect = None
        self.fake.side_effect = lambda argv, **kw: CommandResult(0, b'Linux 6.1.0 x86_64\n' if argv[0] == 'uname' else b'local output\n')
        before = {n: (lab.root / 'hosts' / n / 'README.md').read_bytes() for n in lab.hosts}
        code, results = collect.run(lab, factory=factory)
        self.assertEqual(code, 0)
        self.assertEqual(set(results), {'compute', 'backup', 'workstation', 'storage', 'router'})
        self.assertEqual(set(requested), {'compute', 'backup', 'workstation'})
        self.assertEqual(self.fake.call_count, len(collect.COMMANDS))
        for connection in ssh.values():
            self.assertEqual(len(connection.calls), len(collect.COMMANDS))
        self.assertEqual(results['storage'].result, 'docs-only')
        self.assertFalse((lab.root / 'hosts/router/observed').exists())
        assemble.write(lab)
        index = (lab.root / 'REBUILD.md').read_text()
        for name in lab.hosts:
            self.assertIn(f'[{name}](hosts/{name}/README.md)', index)
            self.assertEqual((lab.root / 'hosts' / name / 'README.md').read_bytes(), before[name])
        self.assertIn('Backup', index)
        self.assertIn('192.0.2.11', index)
        self.assertIn('TODO: IP address', index)
        self.assertIn('never', index)
        self.assertNotEqual((lab.root / 'hosts/workstation/observed/last-collected.txt').read_text().strip(), 'never')
        requested.clear()
        collect.run(lab, ['compute'], factory=factory)
        self.assertEqual(requested, ['compute'])

    def test_dry_run_no_execution_or_writes(self):
        lab = self.lab(['/etc/fstab', '/etc/shadow'])
        before = tree_bytes(lab.root)
        plan = collect.dry_run(lab, verbose=True)
        self.assertIn('hostname', plan)
        self.assertIn('denied config path /etc/shadow: refused', plan)
        self.assertEqual(tree_bytes(lab.root), before)
        self.fake.assert_not_called()

    def test_requested_and_resolved_credentials_never_read(self):
        lab = self.lab(['/etc/shadow', '/etc/sample.conf', '/etc/credentials.json'])
        fake = FakeTransport(files={'/etc/sample.conf': b'unsafe'}, links={'/etc/sample.conf': '/etc/shadow'})
        code, result = collect.run(lab, factory=lambda host: fake)
        self.assertEqual(code, 0)
        self.assertFalse(any(call[0] == 'read' for call in fake.calls))
        self.assertNotIn(('resolve', '/etc/shadow'), fake.calls)
        self.assertNotIn(('resolve', '/etc/credentials.json'), fake.calls)
        self.assertTrue(result['compute'].warnings)

    def test_secret_canary_absent_in_raw_commands_configs_and_warnings(self):
        value = secrets.token_urlsafe(30)
        lab = self.lab(['/etc/sample.conf'])
        raw = (' = '.join(('password', value)) + '\nport = 8080\n').encode()
        fake = FakeTransport(raw, {'/etc/sample.conf': raw})
        code, results = collect.run(lab, factory=lambda host: fake)
        self.assertEqual(code, 0)
        content = b'\n'.join(tree_bytes(lab.root).values())
        self.assertNotIn(value.encode(), content)
        self.assertNotIn(value, repr(results['compute'].warnings))
        self.assertIn(b'refused: secret-like content', content)

    def test_failure_retains_old_capture_and_other_host_continues(self):
        lab = self.lab()
        scaffold.add_host(lab, 'backup', ssh='backup-alias')
        lab = config.load(lab.root)
        good = FakeTransport()
        collect.run(lab, factory=lambda host: good)
        before = tree_bytes(lab.root / 'hosts/compute/observed')
        bad = FakeTransport(secrets.token_bytes(36))
        bad.fail = True
        code, results = collect.run(lab, factory=lambda host: bad if host.name == 'compute' else good)
        self.assertEqual(code, 1)
        self.assertEqual(tree_bytes(lab.root / 'hosts/compute/observed'), before)
        self.assertEqual(results['backup'].result, 'ok')
        self.assertFalse(results['compute'].files)

    def test_refused_or_removed_file_cannot_leave_stale_capture(self):
        lab = self.lab(['/etc/sample.conf'])
        fake = FakeTransport(files={'/etc/sample.conf': b'port = 8080\n'})
        collect.run(lab, factory=lambda host: fake)
        capture = lab.root / 'hosts/compute/observed/configs/1.txt'
        self.assertTrue(capture.exists())
        fake.files['/etc/sample.conf'] = b'\0binary'
        collect.run(lab, factory=lambda host: fake)
        self.assertFalse(capture.exists())
        lab.hosts['compute'].data['files'] = []
        collect.run(lab, factory=lambda host: fake)
        self.assertFalse(capture.exists())

    def test_missing_optional_commands_discard_diagnostics(self):
        lab = self.lab()
        value = secrets.token_urlsafe(30).encode()
        fake = FakeTransport()
        with patch.object(fake, 'run', return_value=CommandResult(127, value, value)):
            code, results = collect.run(lab, factory=lambda host: fake)
        self.assertEqual(code, 0)
        self.assertTrue(results['compute'].warnings)
        self.assertNotIn(value, b'\n'.join(tree_bytes(lab.root).values()))

    def test_select_validation_before_writes(self):
        lab = self.lab()
        before = tree_bytes(lab.root)
        for names in (['unknown'], ['compute', 'compute']):
            with self.assertRaises(ConfigError):
                collect.run(lab, names)
        self.assertEqual(tree_bytes(lab.root), before)

    def test_observed_symlink_refused_before_collection(self):
        lab = self.lab()
        outside = self.root / 'outside'
        outside.mkdir()
        (lab.root / 'hosts/compute/observed').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ConfigError):
            collect.run(lab)
        self.fake.assert_not_called()
