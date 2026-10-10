import secrets
from unittest.mock import patch

from homelab_kit import config, scaffold
from tests.support import HermeticTestCase


class CliTests(HermeticTestCase):
    def test_quickstart_and_repeated_add_host(self):
        root = self.root / 'lab'
        self.assertEqual(self.cli('init', str(root))[0], 0)
        for name, mode in (('compute', ['--ssh', 'operator@192.0.2.10']), ('workstation', ['--local']),
                           ('storage', ['--docs-only']), ('router', [])):
            self.assertEqual(self.cli('--repo', str(root), 'add-host', name, *mode)[0], 0)
        self.assertEqual(len(config.load(root).hosts), 4)
        self.assertEqual(self.cli('--repo', str(root), 'add-service', 'archive', '--host', 'storage')[0], 0)
        self.assertEqual(self.cli('--repo', str(root), 'collect', '--dry-run')[0], 0)
        self.assertEqual(self.cli('--repo', str(root), 'check')[0], 0)
        self.fake.assert_not_called()

    def test_demo_and_example_equivalent(self):
        for command in (('demo', str(self.root / 'demo')), ('init', str(self.root / 'example'), '--example')):
            self.assertEqual(self.cli(*command)[0], 0)
        for name in ('demo', 'example'):
            self.assertEqual(len(config.load(self.root / name).hosts), 2)

    def test_argument_errors_omit_secret_values(self):
        value = secrets.token_urlsafe(36)
        code, out, err = self.cli('not-a-command', value)
        self.assertEqual(code, 2)
        self.assertNotIn(value, out + err)

    def test_errors_are_safe_and_removed_commands_are_absent(self):
        for command in ('plan', 'scan', 'readiness', 'steps', 'brief', 'recovery', 'doctor'):
            self.assertEqual(self.cli(command)[0], 2)
        self.assertEqual(self.cli('--repo', str(self.root / 'missing'), 'collect')[0], 2)
        with patch('homelab_kit.scaffold.init', side_effect=OSError(secrets.token_urlsafe(36))):
            code, out, err = self.cli('init', str(self.root / 'new'))
        self.assertEqual(code, 1)
        self.assertIn('raw diagnostics omitted', out)

    def test_collect_docs_only_and_host_selection(self):
        root = self.root / 'lab'
        scaffold.init(root)
        for name in ('router', 'storage'):
            scaffold.add_host(config.load(root), name)
        code, out, err = self.cli('--repo', str(root), 'collect', '--host', 'storage')
        self.assertEqual(code, 0)
        self.assertIn('storage: docs-only', out)
        self.assertNotIn('router:', out)
        self.fake.assert_not_called()
