import secrets
from unittest.mock import patch

from homelab_kit import check, scaffold
from homelab_kit.runner import CommandResult
from tests.support import HermeticTestCase, tree_bytes


class CheckTests(HermeticTestCase):
    def test_read_only_screen_warns_without_printing_values(self):
        root = self.root / 'lab'
        scaffold.init(root)
        value = secrets.token_urlsafe(36)
        (root / 'notes.md').write_text(' = '.join(('password', value)) + '\nTODO: replace with location\n')
        before = tree_bytes(root)
        code, messages = check.repository(root)
        self.assertEqual(code, 1)
        self.assertIn('notes.md:', '\n'.join(messages))
        self.assertIn('WARNING', '\n'.join(messages))
        self.assertNotIn(value, '\n'.join(messages))
        self.assertEqual(tree_bytes(root), before)

    def test_nested_environment_binary_and_symlink_refused(self):
        root = self.root / 'lab'
        scaffold.init(root)
        (root / '.env').write_text('port = 8080\n')
        (root / 'binary').write_bytes(b'\0')
        (root / 'link').symlink_to(self.root / 'missing')
        code, messages = check.repository(root)
        self.assertEqual(code, 1)
        self.assertEqual(len([m for m in messages if "WARNING" in m]), 3)

    def test_privacy_public_private_and_unknown(self):
        with patch('homelab_kit.check.shutil.which', return_value='/usr/bin/gh'):
            for output, code in ((b'PRIVATE\n', 0), (b'PUBLIC\n', 1)):
                self.fake.side_effect = [CommandResult(0, b'https://example.invalid/example/repository\n'), CommandResult(0, output)]
                self.assertEqual(check.privacy(self.root)[0], code)
            self.fake.side_effect = [CommandResult(1)]
            self.assertIn('unknown', check.privacy(self.root)[1])
        with patch('homelab_kit.check.shutil.which', return_value=None):
            self.assertIn('unknown', check.privacy(self.root)[1])

    def test_check_default_never_invokes_gh(self):
        root = self.root / 'lab'
        scaffold.init(root)
        code, out, err = self.cli('--repo', str(root), 'check')
        self.assertEqual(code, 0)
        self.assertIn('items to fill in (run fill)', out)
        self.fake.assert_not_called()
