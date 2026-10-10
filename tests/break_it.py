"""Independent synthetic capture probes; print case labels and counts, never values."""
import secrets
import tempfile
from pathlib import Path

from homelab_kit import collect, config, scaffold
from homelab_kit.neverlist import denied
from tests.support import tree_bytes
from tests.test_collect import FakeTransport


def reported_cases(value):
    cases = []
    for key in ('pass', 'password', 'passwd', 'passphrase', 'psk', 'auth', 'community',
                'requirepass', 'key', 'salt', 'hash', 'secret', 'token', 'credential',
                'authorization', 'api-key', 'private-key', 'pw'):
        for syntax in ('{key}: "{value}"', 'prefix_{key}={value}', '{{"{key}":["{value}"]}}'):
            cases.append((key + '/' + syntax, syntax.format(key=key, value=value)))
    for directive in ('requirepass', 'masterauth', 'auth', 'rocommunity'):
        cases.append((directive + '/directive', '  ' + directive + ' ' + value + '\n'))
    for prefix in (name + separator for name, separator in
                   [('psk', '='), ('passphrase', ':'), ('wpa_passphrase', '='),
                    ('pass', '='), ('key', '='), ('CACHE_PASS', '=')]):
        cases.append((prefix, prefix + value))
    for flag in ('--admin-password ', '--disk-encryption-' + 'key' + '=',
                 '--api-token ', '--shared-' + 'secret' + '='):
        cases.append((flag, '/usr/bin/example ' + flag + value))
    cases += [('curl short', 'curl -u user:' + value), ('mysql short', 'mysql -p' + value),
              ('hash row', 'operator:$' + '6$' + value),
              ('host row', 'example.invalid:operator:' + value),
              ('CSV export', '"Example",https://example.invalid,operator,"' + value + '",memo'),
              ('CSV header', 'title,website,username,password\nExample,https://example.invalid,operator,' + value),
              ('escaped assignment', 'password\\=\\"' + value + '\\"'),
              ('bracketed pw', '{"pw":["' + value + '"]}'),
              ('single userinfo', 'https://' + value + '@example.invalid/path'),
              ('fullwidth', 'ＡＰＩ＿ＫＥＹ=' + value),
              ('invisible', '\u2060se\u200bcr\ufeffet=' + value)]
    for key in ('private key', 'PgP PrIvAtE KeY BlOcK', 'eC PRIVATE KEY'):
        cases.append((key, '-----' + 'BEGIN ' + key + '-----\n' + value))
    return cases


def new_cases(value):
    return [
        ('curl long option', 'curl --user=operator:' + value),
        ('mysql long option', 'mysql --password=' + value),
        ('FTP userinfo', 'ftp://' + value + '@example.invalid'),
        ('invisible word joiner', 'p\u2060assword=' + value),
        ('BOM-prefixed assignment', '\ufefftoken=' + value),
        ('mixed case nested flag', '--ADMIN-API-TOKEN=' + value),
        ('git header', 'git -c http.extraheader="Authorization: Bearer ' + value + '"'),
        ('YAML sequence', '- ' + 'password' + ':\n  - ' + value),
        ('XML element', '<' + 'password' + '>' + value + '</' + 'password' + '>'),
        ('escaped JSON key', '{"pass\\u0077ord":"' + value + '"}'),
        ('percent encoded key', 'pass%77ord=' + value),
        ('HTML entity key', 'pass&#119;ord=' + value),
        ('Cyrillic lookalike', 'pаssword=' + value),
        ('shell concatenated key', 'pass""word=' + value),
        ('key split across lines', 'pass\nword=' + value),
        ('JavaScript computed key', '{["password"]:"' + value + '"}'),
        ('two-column export', 'operator,' + value),
        ('tab-delimited row', 'Example\toperator\t' + value),
        ('unfamiliar key', 'pin_code=' + value),
        ('natural-language disclosure', 'The recovery phrase is ' + value + '.'),
    ]


PATHS = ('/etc/.htpasswd', '/etc/htpasswd', '/opt/passwd', '/etc/smbpasswd',
         '/etc/ipsec.secrets', '/opt/secrets', '/etc/auth.txt', '/etc/passwd.client',
         '/opt/.vnc/passwd', '/opt/restic-repo-password-file', '/opt/age/keys.txt',
         '/etc/k3s.yaml', '/etc/kubernetes/admin.conf', '/opt/vault.keyring',
         '/opt/backup.1pux', '/opt/backup.1pif', '/opt/vault-export.csv',
         '/opt/vault-export.json', '/proc/123/cmdline', '/opt/id_' + 'rsa-renamed',
         '/opt/key.pem.bak', '/opt/key.key.bak')


def main():
    value = 'fake-' + secrets.token_hex(4)
    reported = reported_cases(value)
    extra = new_cases(value)
    counts = {'reported_content': len(reported), 'reported_refused': 0,
              'paths': len(PATHS), 'paths_refused': 0, 'new': len(extra), 'new_refused': 0,
              'new_slips': 0, 'value_in_diagnostics': 0}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / 'lab'
        scaffold.init(root)
        scaffold.add_host(config.load(root), 'compute', direct=True, files=['/etc/sample.conf'])
        lab = config.load(root)
        for group, cases in (('reported', reported), ('new', extra)):
            for label, text in cases:
                raw = ('port=8080\n' + text + '\ninnocent=yes\n').encode()
                fake = FakeTransport(raw, {'/etc/sample.conf': raw})
                code, result = collect.run(lab, factory=lambda host: fake)
                assert code == 0
                saved = tree_bytes(root / 'hosts/compute/observed')
                diagnostics = '\n'.join(result['compute'].warnings)
                counts['value_in_diagnostics'] += int(value in diagnostics)
                refused = not any(name.startswith(('commands/', 'configs/')) and name != 'commands/kernel.txt' for name in saved)
                counts[group + '_refused'] += int(refused)
                if not refused:
                    assert any(value.encode() in data for data in saved.values())
                    if group == 'new':
                        counts['new_slips'] += 1
                    print('SLIP', group, label)
        for path in PATHS:
            counts['paths_refused'] += int(denied(path, sensitive_name=True) is not None)
    print('COUNTS', counts)
    return int(counts['reported_refused'] != len(reported)
               or counts['paths_refused'] != len(PATHS) or counts['value_in_diagnostics'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
