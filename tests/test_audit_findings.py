"""Audit regressions: secret values exist only in memory, constructed at runtime."""
import os
import secrets
import subprocess
import sys

from homelab_kit import assemble, check, collect, config, scaffold
from homelab_kit.errors import ConfigError
from homelab_kit.neverlist import denied
from homelab_kit.redact import screen
from tests.support import HermeticTestCase, tree_bytes
from tests.test_collect import FakeTransport


def audit_cases(value):
    keys = ('pass', 'password', 'passwd', 'passphrase', 'pwd', 'pw', 'psk', 'auth',
            'community', 'requirepass', 'masterauth', 'key', 'salt', 'hash', 'secret',
            'token', 'credential', 'authorization', 'api-key', 'private-key')
    cases = [(key, key + '=' + value) for key in keys]
    cases += [(key + ' directive', key + ' ' + value) for key in
              ('requirepass', 'masterauth', 'auth', 'rocommunity')]
    cases += [(key, key + value) for key in
              (name + separator for name, separator in
               [('psk', '='), ('passphrase', ':'), ('wpa_passphrase', '='),
                ('pass', '='), ('key', '='), ('DB_PASS', '=')])]
    cases += [('flag', '--admin-' + 'password' + ' ' + value),
              ('flag equals', '--storage-' + 'key' + '=' + value),
              ('curl', 'curl -u ' + 'user:' + value + ' https://example.invalid'),
              ('mysql', 'mysql -p' + value),
              ('htpasswd', 'user:$' + '2y$' + value),
              ('colon row', 'example.invalid:user:' + value),
              ('CSV header', 'name,url,username,password,notes\nexample,https://example.invalid,user,' + value + ',memo'),
              ('CSV row', 'example,https://example.invalid,user,' + value + ',memo'),
              ('escaped', 'password\\="' + value + '"'),
              ('bracketed', '{"pw":["' + value + '"]}'),
              ('userinfo', 'https://' + value + '@example.invalid'),
              ('fullwidth', 'ｐａｓｓｗｏｒｄ=' + value),
              ('zero width', 'p\u200ba\u200cs\u200ds\ufeffword=' + value)]
    return cases


AUDIT_PATHS = ('.htpasswd', 'htpasswd', 'passwd', 'smbpasswd', 'ipsec.secrets', 'secrets',
               'auth.txt', 'passwd.client', '.vnc/passwd', 'restic-backup-password.txt',
               'age/keys.txt', 'k3s.yaml', 'kubernetes/admin.conf', 'vault.keyring',
               'archive.1pux', 'archive.1pif', 'account-export.csv', 'account-export.json',
               'id_' + 'rsa.old', 'server.key.bak', 'server.pem.bak')


class AuditFindingsTests(HermeticTestCase):
    def lab(self, paths=None):
        root = self.root / 'lab'
        scaffold.init(root)
        scaffold.add_host(config.load(root), 'compute', direct=True, files=paths)
        return config.load(root)

    def test_p1_screen_refuses_entire_capture_for_every_reported_shape(self):
        for label, text in audit_cases('fake-' + secrets.token_hex(3)):
            with self.subTest(case=label):
                result = screen('sample.conf', 'port=8080\n' + text + '\ninnocent=yes\n')
                self.assertIsNone(result.text)
                self.assertTrue(result.lines)

    def test_p1_collect_retains_only_source_and_line(self):
        lab = self.lab(['/etc/sample.conf'])
        for label, text in audit_cases('fake-' + secrets.token_hex(3)):
            with self.subTest(case=label):
                raw = ('port=8080\n' + text + '\n').encode()
                fake = FakeTransport(raw, {'/etc/sample.conf': raw})
                code, results = collect.run(lab, factory=lambda host: fake)
                self.assertEqual(code, 0)
                files = tree_bytes(lab.root / 'hosts/compute/observed')
                self.assertFalse(any(name.startswith(('commands/', 'configs/')) and name != 'commands/kernel.txt' for name in files))
                warnings = results['compute'].warnings
                self.assertIn('refused: secret-like content in /etc/sample.conf, line 2', warnings)
                self.assertIn('refused: secret-like content in commands/hostname.txt, line 2', warnings)
                self.assertNotIn(raw, files.values())

    def test_p1_path_denylist(self):
        for tail in AUDIT_PATHS:
            with self.subTest(path=tail):
                self.assertIsNotNone(denied('/etc/' + tail))
        self.assertIsNotNone(denied('/proc/123/cmdline'))

    def test_p1_sensitive_basenames_requested_and_resolved_not_read(self):
        names = ('bypass.conf', 'secretsafe.conf', 'credentials.conf', 'token-cache',
                 'oauth.conf', 'keyring-cache', 'report-export.txt')
        lab = self.lab()
        for name in names:
            for resolved in (False, True):
                with self.subTest(name=name, resolved=resolved):
                    source, target = '/etc/sample.conf', '/etc/' + name
                    lab.hosts['compute'].data['files'] = [source if resolved else target]
                    fake = FakeTransport(files={target: b'port=8080'}, links={source: target})
                    collect.run(lab, factory=lambda host: fake)
                    self.assertFalse(any(call[0] == 'read' for call in fake.calls))
                    if not resolved:
                        self.assertNotIn(('resolve', target), fake.calls)

    def test_p2_preserve_root_readme(self):
        lab = self.lab()
        readme = lab.root / 'README.md'
        readme.write_text('Owner restore notes\n')
        assemble.write(lab)
        self.assertEqual(readme.read_text(), 'Owner restore notes\n')
        self.assertIn('[compute]', (lab.root / 'REBUILD.md').read_text())

    def test_p2_long_sane_file_paths(self):
        path = '/etc/example/configuration-for-the-archive-service-with-long-name/settings.conf'
        lab = self.lab([path])
        self.assertEqual(lab.hosts['compute'].data['files'], [path])
        self.assertEqual(check.repository(lab.root)[0], 0)

    def test_p2_case_insensitive_private_key_headers(self):
        for kind in ('private key', 'rsa Private Key', 'pgp private key block'):
            opening = '-----' + 'BEGIN ' + kind + '-----'
            result = screen('sample.conf', 'port=8080\n' + opening + '\nfake-' + secrets.token_hex(3))
            self.assertIsNone(result.text)
            self.assertEqual(result.lines[0], 2)

    def test_p2_warnings_identify_source(self):
        lab = self.lab(['/etc/sample.conf', '/etc/shadow', '/etc/missing.conf'])
        fake = FakeTransport(files={'/etc/sample.conf': b'\0'})
        result = collect.observe(lab.hosts['compute'], fake)
        for source in ('/etc/sample.conf', '/etc/shadow', '/etc/missing.conf'):
            self.assertIn(source, '\n'.join(result.warnings))

    def test_p3_nested_skipped_names_are_screened(self):
        for name in ('.git', '.venv', '__pycache__'):
            folder = self.root / 'nested' / name
            folder.mkdir(parents=True)
            (folder / 'notes.txt').write_text('='.join(('password', 'fake-' + secrets.token_hex(3))))
        self.assertEqual(check.repository(self.root)[0], 1)
        messages = check.repository(self.root)[1]
        self.assertEqual(len([message for message in messages if "WARNING" in message]), 3)
        self.assertIn("Capture privacy:", messages)

    def test_p3_service_link_escaped(self):
        lab = self.lab()
        (lab.root / 'services' / 'odd[link](name)|<x>.md').write_text('Notes\n')
        document = assemble.document(lab)
        self.assertIn(r'odd\[link\]\(name\)\|&lt;x&gt;', document)
        self.assertIn('services/odd%5Blink%5D%28name%29%7C%3Cx%3E.md', document)

    def test_p3_fifo_read_cannot_hang(self):
        fifo = self.root / 'pipe'
        os.mkfifo(fifo)
        script = ('from homelab_kit.transport import LocalTransport, CaptureFailure\n'
                  'import sys\n'
                  'try:\n'
                  ' LocalTransport({"command_timeout_seconds": 0.05}).read(sys.argv[1], 10)\n'
                  'except CaptureFailure:\n'
                  ' sys.exit(0)\n'
                  'sys.exit(1)\n')
        try:
            result = subprocess.run([sys.executable, '-c', script, str(fifo)],
                                    capture_output=True, timeout=2, check=False)
        except subprocess.TimeoutExpired:
            self.fail('FIFO read exceeded outer deadline')
        self.assertEqual(result.returncode, 0)

    def test_p3_roles_reject_controls_before_writing(self):
        lab = self.lab()
        before = tree_bytes(lab.root)
        for char in ('\n', '\r', '\t', '\x7f', '\x85'):
            with self.subTest(control=ord(char)):
                with self.assertRaises(ConfigError):
                    scaffold.add_host(lab, 'another', role='Example' + char + 'role')
                self.assertEqual(tree_bytes(lab.root), before)

    def test_p3_init_dirs_are_private_even_with_permissive_umask(self):
        root = self.root / 'private-lab'
        root.mkdir(mode=0o755)
        old = os.umask(0)
        try:
            scaffold.init(root, example=True)
        finally:
            os.umask(old)
        for path in (root, *(p for p in root.rglob('*') if p.is_dir())):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_resolved_path_warning_does_not_echo_remote_values(self):
        lab = self.lab(['/etc/sample.conf'])
        value = 'fake-' + secrets.token_hex(3)
        fake = FakeTransport(links={'/etc/sample.conf': '/etc/' + '='.join(('password', value))})
        result = collect.observe(lab.hosts['compute'], fake)
        self.assertNotIn(value, '\n'.join(result.warnings))
        self.assertIn('/etc/sample.conf', '\n'.join(result.warnings))

    def test_large_csv_field_is_refused_without_parser_exception(self):
        text = ('x' * 150000) + ',user,fake-' + secrets.token_hex(3)
        self.assertIsNone(screen('sample.conf', text).text)
