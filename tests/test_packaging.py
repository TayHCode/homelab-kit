import hashlib
import json
import shlex
import tomllib

from tests.support import ROOT, HermeticTestCase


class PackagingTests(HermeticTestCase):
    def test_release_documentation_contract(self):
        data = json.loads((ROOT / 'release-check.json').read_text())
        self.assertEqual(data['approvals'], [])
        self.assertEqual(data['exclude'], [])
        for entry in data['quickstart']:
            line = (ROOT / entry['file']).read_text().splitlines()[entry['line'] - 1]
            self.assertEqual(shlex.split(line), entry['argv'])
        readme = (ROOT / 'README.md').read_text()
        self.assertIn('## Limits', readme)
        self.assertIn('Nothing is\nauto-collected from non-SSH devices', readme)
        self.assertIn('review before pushing', readme.lower())

    def test_metadata_and_package_data(self):
        data = tomllib.loads((ROOT / 'pyproject.toml').read_text())
        self.assertEqual(data['project']['license'], 'MIT')
        self.assertEqual(data['project']['dependencies'], [])
        self.assertEqual(data['project']['requires-python'], '>=3.11')
        self.assertEqual(data['tool']['setuptools']['package-data'], {'homelab_kit': ['data/**/*']})
        self.assertIn('TayHCode', (ROOT / 'LICENSE').read_text())
        templates = list((ROOT / 'homelab_kit/data/templates/host').glob('*'))
        self.assertEqual([path.name for path in templates], ['generic-host.md.tmpl'])

    def test_license_grant_unchanged(self):
        grant = (ROOT / 'LICENSE').read_text().split('Permission is hereby granted', 1)[1]
        normalized = ' '.join(('Permission is hereby granted' + grant).split())
        expected = 'sha256:fe2a9817987f862eaced948f0468c7f51d2fedfc48c5c505b246a49a3870e9a5'
        self.assertEqual('sha256:' + hashlib.sha256(normalized.encode()).hexdigest(), expected)
