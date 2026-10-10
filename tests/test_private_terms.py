import json
import os
from pathlib import Path
from unittest.mock import patch

from tests import privacy_audit as audit
from tests.support import ROOT, HermeticTestCase


class PrivateTermsTests(HermeticTestCase):
    def test_private_terms(self):
        name = os.environ.get('HOMELAB_KIT_DENYLIST')
        if not name:
            self.skipTest('set HOMELAB_KIT_DENYLIST to a term file outside this repo to run this test')
        terms = audit.terms_from(Path(name), ROOT)
        if os.environ.get('HOMELAB_KIT_SCRUB_TERMS'):
            terms += audit.terms_from(Path(os.environ['HOMELAB_KIT_SCRUB_TERMS']), ROOT)
        found = audit.hits(audit.tree_sources(ROOT), terms)
        self.assertFalse(found, 'COUNTS ' + str(len(found)) + ' ' + repr(found))


class TermFormatTests(HermeticTestCase):
    def test_formats_and_safe_locations(self):
        term_path = self.root / 'terms.txt'
        repo = self.root / 'repo'
        term = ''.join(('invented', 'blocked', 'term'))
        for data in ([term], {'terms': [term]}, {'categories': {'example': [term]}},
                     {'categories': {'example': {'terms': [term]}}}):
            term_path.write_text(json.dumps(data))
            self.assertEqual(audit.terms_from(term_path, repo), [term])
        term_path.write_text(term + '\n')
        self.assertEqual(audit.terms_from(term_path, repo), [term])
        found = audit.hits([(term + '/README.md', 'clean\n' + term.upper())], [term])
        self.assertEqual(found, [('[PRIVATE]/README.md', 2)])
        self.assertEqual(audit.hits([('README.md', 'abcword')], ['abc']), [('README.md', 1)])
        for data in ('[]', '{}', 'null', '[1]'):
            term_path.write_text(data)
            with self.assertRaises(ValueError):
                audit.terms_from(term_path, repo)
        with self.assertRaises(ValueError):
            audit.terms_from(term_path, self.root)
        term_path.unlink()
        with self.assertRaises(ValueError):
            audit.terms_from(term_path, repo)

    def test_tracked_ignored_and_untracked_files_are_checked(self):
        tracked = self.root / 'tracked.txt'
        untracked = self.root / 'untracked.txt'
        term = ''.join(('invented', 'blocked', 'term'))
        for path in (tracked, untracked):
            path.write_text('prefix' + term + 'suffix')
        with patch.object(audit, 'ROOT', self.root), patch.object(audit, 'repo_files', return_value=[tracked, untracked]):
            self.assertEqual(len(audit.hits(audit.tree_sources(self.root), [term])), 2)

    def test_artifact_scans_all_refs_metadata_paths_and_blobs(self):
        term = ''.join(('invented', 'blocked', 'term'))
        root = self.root / 'artifact'
        replies = {
            ('rev-parse', '--is-shallow-repository'): b'false\n',
            ('rev-list', '--all', 'HEAD'): b'commit-a\n',
            ('for-each-ref', '--format=%(refname)'): b'refs/heads/main\n',
            ('show', '-s', '--format=%an%n%ae%n%cn%n%ce%n%B', 'commit-a'): b'clean',
            ('ls-tree', '-rz', '--full-tree', 'commit-a'): b'100644 blob object-a\tREADME.md\0',
            ('cat-file', 'blob', 'object-a'): b'clean',
            ('rev-list', '--objects', '--no-object-names', '--all', 'HEAD'): b'object-a\n',
            ('cat-file', '-t', 'object-a'): b'blob\n',
        }
        def fake(*args):
            self.assertEqual(args[:3], ('-C', str(root), '--no-replace-objects'))
            return replies[args[3:]]
        with patch.object(audit, 'audit_git', side_effect=fake):
            self.assertEqual(audit.hits(audit.artifact_sources(root), [term]), [])
            for key in list(replies):
                if key[:2] == ('cat-file', '-t'):
                    continue
                if key[0] not in ('show', 'cat-file', 'ls-tree') and key != ('for-each-ref', '--format=%(refname)'):
                    continue
                original = replies[key]
                replies[key] = original.replace(b'README.md', (term + '.md').encode()) if key[0] == 'ls-tree' else original + term.encode()
                self.assertTrue(audit.hits(audit.artifact_sources(root), [term]))
                replies[key] = original
            object_key = ('rev-list', '--objects', '--no-object-names', '--all', 'HEAD')
            replies[object_key] += b'object-b\ntag-a\ntree-a\n'
            replies[('cat-file', '-t', 'object-b')] = b'blob\n'
            replies[('cat-file', 'blob', 'object-b')] = term.encode()
            replies[('cat-file', '-t', 'tag-a')] = b'tag\n'
            replies[('cat-file', 'tag', 'tag-a')] = term.encode()
            replies[('cat-file', '-t', 'tree-a')] = b'tree\n'
            replies[('ls-tree', '-rz', '--full-tree', 'tree-a')] = b'100644 blob object-b\t' + term.encode() + b'.md\0'
            self.assertEqual(len(audit.hits(audit.artifact_sources(root), [term])), 3)
            replies[('rev-list', '--all', 'HEAD')] += b'commit-b\n'
            replies[('show', '-s', '--format=%an%n%ae%n%cn%n%ce%n%B', 'commit-b')] = b'clean'
            replies[('ls-tree', '-rz', '--full-tree', 'commit-b')] = b''
            with self.assertRaises(ValueError):
                list(audit.artifact_sources(root))
            replies[('rev-parse', '--is-shallow-repository')] = b'true\n'
            with self.assertRaises(ValueError):
                list(audit.artifact_sources(root))
