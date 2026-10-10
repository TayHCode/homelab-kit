# Secret locations only

Use `secret: <where it lives>` or `secret: <where it lives>` (for example, password manager entry "example-admin").
Record locations, never values. Do not paste original appliance exports.

neverlist.py excludes credential paths, environment files, private keys, wallets,
password-manager data and browser profiles. Config collection checks both requested
and resolved paths before reading. redact.py is a small line screen shared by
collection and the read-only `check`: any secret-like hit refuses the entire
capture. Warnings name the source and first flagged line, never the value.
Sensitive config basenames, credential files and CSV-shaped rows are refused.
Legacy location/redaction markers remain safe on recheck.

This is a safety net, not a guarantee. Review captured output before pushing to your
own private repo. Keep a password-manager recovery route outside the lab.
No fingerprints, approvals, secret-value hashes or per-secret state are maintained.
