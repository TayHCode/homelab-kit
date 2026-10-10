"""Strict local tree checks and an explicit publication-artifact history guard."""
import argparse
import json
import os
import re
from bisect import bisect_right
from pathlib import Path

from tests.support import ROOT, audit_git, repo_files


def terms_from(path: Path, root: Path) -> list[str]:
    if path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Term file must be outside the audited repo')
    try:
        text = path.read_text(encoding='utf-8')
        try:
            data = json.loads(text)
        except ValueError:
            data = [line.strip() for line in text.splitlines() if line.strip()]
        if isinstance(data, dict):
            if 'terms' in data:
                data = data['terms']
            else:
                data = [term for group in data.get('categories', {}).values()
                        for term in (group.get('terms', []) if isinstance(group, dict) else group)]
        if not isinstance(data, list) or not data or not all(isinstance(t, str) and t for t in data):
            raise ValueError
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError):
        raise ValueError('Term file missing, unreadable, invalid or empty') from None
    return data


def hits(sources, terms):
    """Literal case-insensitive substrings, including short terms; safe locations only."""
    patterns = [re.compile(re.escape(term), re.I) for term in terms]
    result = []
    for label, contents in sources:
        safe_label = label
        for pattern in patterns:
            safe_label = pattern.sub('[PRIVATE]', safe_label)
        starts = [m.start() for m in re.finditer('\n', contents)]
        for pattern in patterns:
            result.extend((safe_label, bisect_right(starts, m.start()) + 1)
                          for m in pattern.finditer(contents))
    return result


def tree_sources(root: Path):
    if root == ROOT:
        paths = repo_files()
    else:
        names = audit_git('-C', str(root), 'ls-files', '-co', '--exclude-standard', '-z')
        if names is None:
            raise ValueError('Cannot enumerate artifact files')
        paths = sorted({root / name.decode() for name in names.split(b'\0') if name})
    for path in paths:
        name = path.relative_to(root).as_posix()
        yield name + ':path', name
        if path.is_symlink():
            raise ValueError('Cannot audit a symlink')
        try:
            yield name, path.read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            raise ValueError('Cannot read an audited file') from None


def artifact_sources(root: Path):
    def git(*args):
        value = audit_git('-C', str(root), '--no-replace-objects', *args)
        if value is None:
            raise ValueError('Cannot read complete artifact history')
        return value
    if git('rev-parse', '--is-shallow-repository').strip() != b'false':
        raise ValueError('Artifact history must be complete')
    commits = git('rev-list', '--all', 'HEAD').decode().splitlines()
    refs = git('for-each-ref', '--format=%(refname)').decode()
    yield 'refs', refs
    seen_blobs = set()
    for commit in commits:
        yield commit + ':metadata', git('show', '-s', '--format=%an%n%ae%n%cn%n%ce%n%B', commit).decode()
        for entry in git('ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
            if not entry:
                continue
            info, name = entry.split(b'\t', 1)
            mode, kind, oid = info.decode().split()
            label = commit + '/' + name.decode()
            yield label + ':path', name.decode()
            if kind != 'blob' or mode not in ('100644', '100755'):
                raise ValueError('Artifact contains an unsupported file type')
            yield label, git('cat-file', 'blob', oid).decode('utf-8')
            seen_blobs.add(oid)
    # Refs can point to trees, blobs or nested annotated tags as well as commits.
    # Inspect all reachable objects, including ones absent from commit snapshots.
    objects = git('rev-list', '--objects', '--no-object-names', '--all', 'HEAD').decode().splitlines()
    for oid in objects:
        kind = git('cat-file', '-t', oid).decode().strip()
        if kind == 'tag':
            yield oid + ':tag', git('cat-file', 'tag', oid).decode('utf-8')
        elif kind == 'blob' and oid not in seen_blobs:
            yield oid + ':blob', git('cat-file', 'blob', oid).decode('utf-8')
        elif kind == 'tree':
            for entry in git('ls-tree', '-rz', '--full-tree', oid).split(b'\0'):
                if not entry:
                    continue
                info, name = entry.split(b'\t', 1)
                mode, child_kind, child_oid = info.decode().split()
                yield oid + '/' + name.decode() + ':path', name.decode()
                if child_kind != 'blob' or mode not in ('100644', '100755'):
                    raise ValueError('Artifact contains an unsupported file type')
    if len(set(commits)) != 1:
        raise ValueError('Publication artifact must contain exactly one commit across all refs and HEAD')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', type=Path, required=True)
    args = parser.parse_args()
    try:
        root = args.artifact.resolve()
        terms = []
        for name in ('HOMELAB_KIT_DENYLIST', 'HOMELAB_KIT_SCRUB_TERMS'):
            if not os.environ.get(name):
                raise ValueError('Both external term-list variables are required')
            terms.extend(terms_from(Path(os.environ[name]), root))
        found = hits(tree_sources(root), terms) + hits(artifact_sources(root), terms)
        print('COUNTS', len(found))
        for path, line in found:
            print(f'{path}:{line}')
        return 1 if found else 0
    except (ValueError, UnicodeError):
        print('Artifact privacy audit incomplete or history is not a single complete commit')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
