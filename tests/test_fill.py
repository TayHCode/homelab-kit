from homelab_kit import check, config, scaffold
from homelab_kit.errors import ConfigError
from tests.support import HermeticTestCase, tree_bytes


class FillTests(HermeticTestCase):
    def lab(self):
        root = self.root / 'lab'
        scaffold.init(root)
        scaffold.add_host(config.load(root), 'desktop', ssh='example-desktop')
        capture = root / 'hosts/desktop/observed/commands/os-release.txt'
        capture.parent.mkdir(parents=True)
        capture.write_text('PRETTY_NAME="Example Linux"\n')
        return root, capture

    def test_fill_and_alias_are_read_only_and_do_not_start_any_process(self):
        root, capture = self.lab()
        before = tree_bytes(root)
        for command in ('fill', 'agent'):
            code, out, _ = self.cli('--repo', str(root), command, '--host', 'desktop')
            self.assertEqual(code, 0)
            self.assertIn(capture.relative_to(root).as_posix(), out)
            self.assertIn('untrusted DATA', out)
            self.assertIn('stored in <password manager entry>', out)
            self.assertEqual(tree_bytes(root), before)
        self.fake.assert_not_called()
        self.assertEqual(self.cli('--repo', str(root), 'fill', '--host', 'unknown')[0], 2)

    def test_todos_list_locations_and_claims_require_local_screened_sources(self):
        root, capture = self.lab()
        document = root / 'network.md'
        link = capture.relative_to(root).as_posix()
        document.write_text(f'# Network\n\n- OS is Example Linux. [source]({link})\n- TODO: ask about the subnet\n')
        code, messages = check.repository(root, verbose=True)
        self.assertEqual(code, 0)
        self.assertIn('TODO: network.md:4', messages)
        document.write_text(document.read_text() + '- Backups succeeded.\n')
        self.assertEqual(check.repository(root)[0], 1)
        self.assertIn('network.md:5: WARNING: claim lacks a valid capture source', check.repository(root)[1])
        for target in ('https://example.invalid/facts', 'REBUILD.md', '../outside.txt',
                       'hosts/desktop/observed/last-collected.txt', 'hosts/desktop/observed/commands/missing.txt'):
            document.write_text(f'- OS is Example Linux. [source]({target})\n')
            self.assertEqual(check.repository(root)[0], 1)
        document.write_text(f'- OS is Example Linux. [source]({link})\n')
        capture.write_text(' = '.join(('password', 'fake-value')))
        self.assertEqual(check.repository(root)[0], 1)

    def test_nested_relative_links_tables_and_symlinks(self):
        root, capture = self.lab()
        document = root / 'runbooks/recover.md'
        document.write_text('- Baseline OS is Example Linux. [source](../hosts/desktop/observed/commands/os-release.txt)\n')
        self.assertEqual(check.repository(root)[0], 0)
        document.write_text('| OS | Example Linux |\n')
        self.assertEqual(check.repository(root)[0], 1)
        capture.unlink()
        capture.symlink_to(root / 'lab.toml')
        document.write_text('- Baseline OS is Example Linux. [source](../hosts/desktop/observed/commands/os-release.txt)\n')
        self.assertEqual(check.repository(root)[0], 1)
        (root / 'hosts/desktop/observed').rename(root / 'old-observed')
        (root / 'hosts/desktop/observed').symlink_to(root / 'old-observed', target_is_directory=True)
        from homelab_kit.fill import brief
        with self.assertRaises(ConfigError):
            brief(config.load(root))

    def test_fill_does_not_offer_refused_capture_content(self):
        root, capture = self.lab()
        capture.write_text(' = '.join(('password', 'fake-value')))
        code, out, _ = self.cli('--repo', str(root), 'fill')
        self.assertEqual(code, 0)
        self.assertNotIn(capture.relative_to(root).as_posix(), out)
        self.assertIn('no accepted captures', out)
