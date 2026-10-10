import secrets

from homelab_kit.redact import MARKER, screen
from tests.support import HermeticTestCase


class ScreenTests(HermeticTestCase):
    def test_assignments_refuse_whole_files(self):
        for key in ('password', 'db_password', 'secret', 'token', 'api_key', 'private_key', 'credential', 'Authorization'):
            for syntax in ('{} = {}\n', '"{}": "{}"\n', '- {}: {}\n'):
                with self.subTest(key=key, syntax=syntax):
                    value = secrets.token_hex(3)
                    result = screen('settings.conf', syntax.format(key, value) + 'port = 8080\n')
                    self.assertIsNone(result.text)
                    self.assertEqual(result.lines, (1,))
                    self.assertIn("refused:", result.warning)
                    self.assertNotIn(value, result.warning)

    def test_embedded_auth_urls_and_random_strings(self):
        value = secrets.token_urlsafe(36)
        for line in ('Bearer ' + value, 'postgresql://user:' + value + '@example.invalid/db',
                     'header = ' + value, '--password ' + value):
            result = screen('output.txt', line + '\nport = 8080\n')
            self.assertIsNone(result.text)
            self.assertTrue(result.warning)

    def test_key_blocks_refused_even_without_end(self):
        opening = '-----' + 'BEGIN ' + 'PRIVATE KEY-----'
        for text in (opening, opening + '\n' + secrets.token_urlsafe(40) + '\n-----END ' + 'PRIVATE KEY-----'):
            self.assertIsNone(screen('sample.txt', text).text)

    def test_multiline_values_refused(self):
        for key, body in (('password', '|\n  short\n'), ('token', '{\n "value": "short"\n}'), ('secret', '\n  nested: short\n')):
            text = key + ': ' + body
            self.assertIsNone(screen('sample.conf', text).text)

    def test_dense_secret_files_refused(self):
        text = '\n'.join(key + ' = ' + secrets.token_hex(3) for key in ('password', 'token', 'secret'))
        self.assertIsNone(screen('sample.conf', text).text)

    def test_credential_paths_refused(self):
        for path in ('.env', '.env.production', 'stack.env', 'credentials.json', 'wallet.dat', '.kube/config', 'id_' + 'rsa'):
            with self.subTest(path=path):
                self.assertIsNone(screen(path, 'port = 8080\n').text)

    def test_locations_and_redactions_are_safe_on_recheck(self):
        for text in ('secret: <where it lives>\n', ': '.join(('secret', 'password manager entry "example-admin"\n')), MARKER + '\n'):
            result = screen('notes.md', text)
            self.assertEqual(result.text, text)
            self.assertFalse(result.warning)

    def test_location_with_appended_secret_is_not_exempt(self):
        value = secrets.token_urlsafe(36)
        text = ': '.join(('secret', 'password manager entry "example-admin"')) + '; ' + '='.join(('token', value))
        self.assertIsNone(screen('notes.md', text).text)
