"""Retained leak regression checks adapted to raw output and the small screen."""
import secrets
from unittest.mock import patch

from homelab_kit import config, scaffold
from homelab_kit.redact import screen
from tests.support import HermeticTestCase, tree_bytes
from tests.test_collect import FakeTransport


class SecretLeakTests(HermeticTestCase):
    def lab(self):
        root = self.root / 'lab'
        scaffold.init(root)
        scaffold.add_host(config.load(root), 'compute', ssh='compute-alias', files=['/etc/sample.conf'])
        return config.load(root)

    def test_all_disk_and_cli_output_omit_canaries(self):
        lab = self.lab()
        value = secrets.token_urlsafe(36)
        raw = (' = '.join(('password', value)) + '\nport = 8080\n').encode()
        connection = FakeTransport(raw, {'/etc/sample.conf': raw})
        with patch('homelab_kit.transport.for_host', return_value=connection):
            code, out, err = self.cli('--repo', str(lab.root), 'collect')
        self.assertEqual(code, 0)
        self.assertIn('refused:', out)
        self.assertNotIn(value, out + err)
        for name, data in tree_bytes(lab.root).items():
            self.assertNotIn(value, name)
            self.assertNotIn(value.encode(), data)
        self.assertNotIn('hosts/compute/observed/configs/1.txt', tree_bytes(lab.root))

    def test_cross_product_short_values_and_common_shapes(self):
        for size in (3, 8, 13, 20):
            value = ('9Z' + secrets.token_urlsafe(30))[:size]
            for key in ('password', 'db_password', 'secret', 'token', 'api_key', 'private_key', 'authorization'):
                for shape in ('{key}="{value}"', '{key}: {value}', '{{"{key}":"{value}"}}',
                              '{key} {value};', 'ExecStart=/usr/bin/example --{key}={value}'):
                    with self.subTest(size=size, key=key, shape=shape):
                        result = screen('/etc/sample.conf', shape.format(key=key, value=value))
                        self.assertNotIn(value, result.text or '')
                        self.assertNotIn(value, result.warning)

    def test_transport_exception_and_stderr_never_surface(self):
        lab = self.lab()
        value = secrets.token_urlsafe(36)
        connection = FakeTransport()
        with patch.object(connection, 'run', side_effect=RuntimeError(value)), patch('homelab_kit.transport.for_host', return_value=connection):
            code, out, err = self.cli('--repo', str(lab.root), 'collect')
        self.assertEqual(code, 1)
        self.assertNotIn(value, out + err)
        self.assertFalse((lab.root / 'hosts/compute/observed').exists())

    def test_explicit_multiline_and_continuations_refused(self):
        value = secrets.token_urlsafe(10)
        for text in ('password' + ' = "prefix\n' + value + '"', 'secret' + ' = prefix\\\n' + value):
            self.assertIsNone(screen('/etc/sample.conf', text).text)
