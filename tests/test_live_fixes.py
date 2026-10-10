"""Regressions found by running the kit against real Linux, macOS, Windows and appliance hosts."""
import json
import secrets

from homelab_kit import assemble, check, collect, config, scaffold, transport
from homelab_kit.redact import screen
from homelab_kit.runner import CommandResult
from tests.support import HermeticTestCase
from tests.test_collect import FakeTransport


class ScreenFalsePositiveTests(HermeticTestCase):
    def test_json_command_output_is_not_a_csv_row(self):
        text = json.dumps([{"ifname": "eth0", "addr_info": [{"local": "192.0.2.10", "prefixlen": 24}]}])
        self.assertIsNotNone(screen('commands/addresses.txt', text + '\n').text)

    def test_json_with_secret_keys_is_still_refused(self):
        text = json.dumps({"name": "x", "password": secrets.token_hex(3), "mode": "y"})
        self.assertIsNone(screen('commands/x.txt', text).text)

    def test_comments_and_toml_arrays_with_commas_are_not_csv_rows(self):
        text = '# See man pages fstab(5), findfs(8), mount(8) and/or blkid(8) for more info.\n'
        self.assertIsNotNone(screen('/etc/fstab', text).text)
        self.assertIsNotNone(screen('host.toml', 'files = ["/etc/a", "/etc/b", "/etc/c"]\n').text)
        self.assertIsNone(screen('x.csv', 'site,user,login\nexample.invalid,example-user,value\n').text)

    def test_bypass_is_not_a_password_key_but_password_still_is(self):
        self.assertIsNotNone(screen('cpu.txt', 'Vulnerability Spec store ' + 'bypass' + ': Mitigation; disabled\n').text)
        self.assertIsNone(screen('cpu.txt', 'Spec ' + 'bypass_password' + ': ' + secrets.token_hex(3) + '\n').text)

    def test_boolean_directive_values_pass_but_values_do_not(self):
        self.assertIsNotNone(screen('sshd_config', 'PasswordAuthentication no\nPermitEmptyPasswords no\n').text)
        self.assertIsNone(screen('sshd_config', ' '.join(('password', secrets.token_hex(3))) + '\n').text)

    def test_listing_flag_skips_only_the_random_string_check(self):
        name = 'a-long-hyphenated-unit-or-url-name-with-many-letters.timer\n'
        self.assertIsNotNone(screen('t.txt', name.replace('.timer', '')).text)
        value = secrets.token_urlsafe(40)
        self.assertIsNone(screen('t.txt', value).text)
        self.assertIsNotNone(screen('t.txt', value, listing=True).text)
        self.assertIsNotNone(screen('t.txt', name.replace('.timer', ''), listing=True).text)
        self.assertIsNone(screen('t.txt', 'password = ' + secrets.token_hex(3), listing=True).text)

    def test_fstab_rows_and_authentication_headings_pass(self):
        row = 'tank/data\t/mnt/data\tzfs\trw,noatime,nofail,x-example=1\t0\t0\n'
        self.assertIsNotNone(screen('/etc/fstab', row).text)
        self.assertIsNotNone(screen('sshd_config', '# Authentication:\n').text)
        self.assertIsNone(screen('x.conf', 'authentication: ' + secrets.token_hex(3) + '\n').text)

    def test_uuid_passes_but_other_long_tokens_do_not(self):
        uuid = '-'.join(secrets.token_hex(n) for n in (4, 2, 2, 2, 6))
        self.assertIsNotNone(screen('/etc/fstab', 'UUID=' + uuid + ' / ext4 defaults 0 1\n').text)
        self.assertIsNone(screen('/etc/x.conf', 'v ' + secrets.token_urlsafe(40) + '\n').text)

    def test_vendor_token_shapes_are_refused(self):
        key_id = 'AK' + 'IA' + secrets.token_hex(8).upper()
        self.assertIsNone(screen('a.conf', 'x\nid ' + key_id + '\n').text)
        self.assertIsNone(screen('a.conf', 'v ' + 'gh' + 'p_' + secrets.token_hex(10) + '\n').text)


class RealHostCollectionTests(HermeticTestCase):
    def lab(self, paths=None):
        root = self.root / 'lab'
        scaffold.init(root)
        scaffold.add_host(config.load(root), 'compute', ssh='operator@192.0.2.10', files=paths)
        return config.load(root)

    def test_unreadable_file_warns_without_losing_the_host_capture(self):
        class Denied(FakeTransport):
            def read(self, path, limit):
                if path == '/etc/locked.conf':
                    raise transport.Unreadable(operation='read', path=path)
                return super().read(path, limit)
        lab = self.lab(['/etc/locked.conf', '/etc/open.conf'])
        fake = Denied(files={'/etc/locked.conf': b'x', '/etc/open.conf': b'port=8080\n'})
        code, results = collect.run(lab, factory=lambda host: fake)
        self.assertEqual(code, 0)
        self.assertTrue(any('/etc/locked.conf unreadable' in w for w in results['compute'].warnings))
        self.assertEqual((lab.root / 'hosts/compute/observed/configs/2.txt').read_text(), 'port=8080\n')

    def test_local_and_ssh_reads_report_unreadable_files(self):
        local = transport.LocalTransport(config.SETTINGS)
        self.fake.side_effect = None
        self.fake.return_value = CommandResult(1)
        with self.assertRaises(transport.Unreadable):
            local.read('/etc/locked.conf', 100)
        with self.assertRaises(transport.Unreadable):
            transport.SshTransport('operator@192.0.2.10', config.SETTINGS).read('/etc/locked.conf', 100)

    def test_unsupported_bsd_host_gets_one_notice_and_no_capture(self):
        class Bsd(FakeTransport):
            def run(self, argv):
                self.calls.append(('run', tuple(argv)))
                return CommandResult(0, b'FreeBSD 14.0 arm64\n') if argv[0] == 'uname' else CommandResult(127)
        lab = self.lab()
        fake = Bsd()
        code, results = collect.run(lab, factory=lambda host: fake)
        self.assertEqual(code, 0)
        self.assertEqual(results['compute'].result, 'unsupported')
        self.assertEqual(len(results['compute'].warnings), 1)
        self.assertEqual(len(fake.calls), 1)
        self.assertFalse((lab.root / 'hosts/compute/observed').exists())

    def test_missing_uname_and_powershell_are_reported_as_unsupported(self):
        class Windows(FakeTransport):
            def run(self, argv):
                return CommandResult(1)
        lab = self.lab()
        _, results = collect.run(lab, factory=lambda host: Windows())
        self.assertEqual(results['compute'].result, 'unsupported')

    def test_observed_readme_names_the_source_of_numbered_configs(self):
        lab = self.lab(['/etc/sample.conf'])
        collect.run(lab, factory=lambda host: FakeTransport(files={'/etc/sample.conf': b'port=8080\n'}))
        observed = (lab.root / 'hosts/compute/observed/README.md').read_text()
        self.assertIn('- [configs/1.txt](configs/1.txt) (/etc/sample.conf)', observed)

    def test_index_shows_os_and_observed_readme_lists_captures(self):
        lab = self.lab()
        text = b'PRETTY_NAME="Example Linux 1.0"\nID=example\n'
        class Linux(FakeTransport):
            def run(self, argv):
                if argv[0] == 'uname':
                    return CommandResult(0, b'Linux 6.1.0 x86_64\n')
                return CommandResult(0, text if argv[0] == 'cat' and argv[1] == '/etc/os-release' else b'ok\n')
        collect.run(lab, factory=lambda host: Linux())
        assemble.write(lab)
        index = (lab.root / 'REBUILD.md').read_text()
        self.assertIn('| OS (observed) |', index)
        self.assertIn('Example Linux 1.0', index)
        observed = (lab.root / 'hosts/compute/observed/README.md').read_text()
        self.assertIn('- [commands/os-release.txt](commands/os-release.txt)', observed)

    def test_check_applies_the_collection_policy_to_observed_inventories(self):
        lab = self.lab()
        observed = lab.root / 'hosts/compute/observed/commands'
        observed.mkdir(parents=True)
        (observed / 'units-enabled.txt').write_text('a-very-long-hyphenated-and-quite-ordinary-unit-name.service enabled\n')
        self.assertEqual(check.repository(lab.root)[0], 0)
        (observed / 'user-crontab.txt').write_text(secrets.token_urlsafe(40) + '\n')
        self.assertEqual(check.repository(lab.root)[0], 1)

    def test_check_accepts_a_host_with_several_collected_files(self):
        lab = self.lab(['/etc/a.conf', '/etc/b.conf', '/etc/c.conf', '/etc/d.conf'])
        code, messages = check.repository(lab.root)
        self.assertEqual([m for m in messages if 'WARNING' in m], [])
        self.assertEqual(code, 0)
