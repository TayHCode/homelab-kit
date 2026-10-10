from homelab_kit import assemble, check, config, scaffold
from homelab_kit.errors import ConfigError
from tests.support import HermeticTestCase, tree_bytes


class ScaffoldTests(HermeticTestCase):
    def test_init_plain_markdown_and_check(self):
        root = self.root / 'lab'
        scaffold.init(root)
        for name in ('README.md', 'REBUILD.md', 'network.md', 'services.md', 'backups.md', 'AGENTS.md', 'runbooks/_TEMPLATE.md'):
            self.assertTrue((root / name).is_file())
        self.assertEqual(check.repository(root)[0], 0)
        self.assertEqual(config.load(root).hosts, {})

    def test_demo_is_two_hosts_and_makes_no_calls(self):
        root = self.root / 'demo'
        scaffold.demo(root)
        lab = config.load(root)
        self.assertEqual(len(lab.hosts), 2)
        self.assertEqual({host.kind for host in lab.hosts.values()}, {'ssh', 'docs'})
        self.assertEqual(check.repository(root)[0], 0)
        self.fake.assert_not_called()

    def test_refuse_existing_destinations(self):
        root = self.root / 'lab'
        scaffold.init(root)
        scaffold.add_host(config.load(root), 'example-storage')
        before = tree_bytes(root)
        with self.assertRaises(ConfigError):
            scaffold.init(root)
        with self.assertRaises(ConfigError):
            scaffold.add_host(config.load(root), 'example-storage')
        self.assertEqual(tree_bytes(root), before)

    def test_generic_template_modes_and_export_pointer(self):
        root = self.root / 'lab'
        scaffold.init(root)
        for name, options in (('compute', {'ssh': 'operator@192.0.2.10'}), ('workstation', {'direct': True}),
                              ('storage', {'config_export': 'Encrypted offline storage: export folder'})):
            scaffold.add_host(config.load(root), name, **options)
            self.assertIn('## Hardware and installation', (root / 'hosts' / name / 'README.md').read_text())
        doc = assemble.document(config.load(root))
        self.assertIn('TODO: IP address', doc)
        self.assertIn('never', doc)
        self.assertIn('Encrypted offline storage:', (root / 'hosts/storage/README.md').read_text())

    def test_services_link_to_host_and_backups(self):
        root = self.root / 'lab'
        scaffold.init(root, example=True)
        for template in ('service', 'local-llm', 'remote-browser'):
            scaffold.add_service(config.load(root), template, 'example-storage', template)
            service = (root / 'services' / (template + '.md')).read_text()
            self.assertIn('../hosts/example-storage/README.md', service)
            self.assertIn('../backups.md', service)
            self.assertIn('../../services/' + template + '.md', (root / 'hosts/example-storage/README.md').read_text())
        self.assertEqual(check.repository(root)[0], 0)

    def test_invalid_inputs_and_old_schema_do_not_mutate(self):
        root = self.root / 'lab'
        scaffold.init(root)
        before = tree_bytes(root)
        for name, options in (('../escape', {}), ('valid', {'ssh': '-bad'}), ('valid', {'role': ' = '.join(('password', 'short'))}),
                              ('valid', {'files': ['/etc/../shadow']})):
            with self.assertRaises(ConfigError):
                scaffold.add_host(config.load(root), name, **options)
            self.assertEqual(tree_bytes(root), before)
        (root / 'lab.toml').write_text('schema = 1\n')
        with self.assertRaises(ConfigError):
            config.load(root)

    def test_symlink_paths_refused(self):
        root = self.root / 'lab'
        scaffold.init(root)
        (root / 'hosts').rmdir()
        outside = self.root / 'outside'
        outside.mkdir()
        (root / 'hosts').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ConfigError):
            config.load(root)
        self.assertEqual(list(outside.iterdir()), [])
