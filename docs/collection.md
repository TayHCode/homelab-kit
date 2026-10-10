# Collection

Run `collect --dry-run` for a compact summary without connections or writes; add
`--verbose` to see every fixed read-only Linux/macOS/Windows command. Actual
collection uses the retained bounded local/SSH transport and runner.
It runs sequentially across all hosts, or the names supplied with `--host`.
SSH uses `-T` to suppress pseudo-terminal warnings, disables prompts, requires a previously trusted host key, closes stdin
and limits connection establishment to 10 seconds. Each command has a 10-second
execution budget, within a shared 60-second budget for the host. Process startup
and cleanup add overhead; an unreachable host can take about 11 seconds. Expiry
kills the local process tree (Windows uses a kill-on-close job), retains the
previous observation and continues with the next host. Windows captures stay in
memory through pipes that support asynchronous writes from its native OpenSSH
client. No multiplexing options are added. The first connection fix is to verify
the fingerprint and run `ssh HOST true` interactively once on the control account.
Docs-only hosts receive no commands. There are no custom command hooks or parsers.

Set literal absolute paths or quoted `~/...` paths in each host.toml `files`
array, or repeat `add-host --file PATH`. Local absolute paths under the collecting
account's home are stored with `~`; `~/...` resolves on the collecting host,
including over SSH. Other users' remote absolute paths are preserved.
Missing local files warn at add time without preventing host creation.
Paths and resolved paths pass the denylist before any read; credential
filenames are refused, including basenames containing pass, secret, cred, token,
auth, keyring or export. There is no override. No globs are expanded. Non-UTF-8, binary and oversized
files are refused; config files are capped at 256 KiB. Every successful raw command
output passes the same line screen; any hit refuses the entire capture and
records only its source and first flagged line. Accepted files are saved under observed/configs
with numbers matching their order in `files`; commands use observed/commands.
Labels use the supplied target path, with home/user directories abbreviated to
`~/...`, never the control machine's resolved path. Absolute drive-letter paths
are accepted in inventories on every control OS; Windows custom files remain
skipped except for credential-class paths, which are refused before reading.
Accepted text has collecting-user home prefixes abbreviated to `~` after the
secret screen. Hostnames, IPs, account names and other paths can remain: review
every capture before staging or committing. `check` names files with privacy
patterns without printing their matched values; `check --strict` fails on them.
This heuristic cannot replace manual review.

Unavailable commands, unreadable files (for example root-only permissions) and refused
files generate warnings and an honest partial/refused/unreadable host status,
with details in observed/README.md, which also links each accepted capture.
Missing tools are named, local command failures never suggest SSH setup, and
permission failures identify the fact and explain how to skip it. No user crontab
is normal: it appears under Not present without a warning or partial status.
Linux and Darwin use uname; a missing uname triggers a PowerShell platform probe.
Unsupported systems are skipped with a single notice. Windows uses fixed
PowerShell scripts through cmd, without env or POSIX quoting. Its only file read
is the built-in hosts file; custom files are skipped. Mac listed config files
resolve symlinks through /bin/sh before path screening; /etc/hosts is built in.
Windows installed programs come only from selected machine uninstall subkeys.
No task actions, service command lines, browser profiles or registry hives are read.
Connection failure, timeout or output overflow retains the previous host capture.
A complete new observation replaces the old one, so removed config paths and
newly refused files cannot leave stale copies. Hand-written Markdown is preserved.
The timestamp means the collection attempt completed, not all data was obtained.
Re-run and review `git diff`; no background update or drift calculation exists.
