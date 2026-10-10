# homelab-kit

Get Markdown documentation of how your homelab works, kept in **your own private
repository**. Collect screened facts and selected config files from Linux, macOS
and Windows hosts over SSH, then use `fill` to give your own agent a brief for
the human parts: network, services, backups and runbooks, with source links.
One generic template covers every machine; add as many hosts as you need.
Python 3.11+; no runtime Python dependencies.

The kit generates a REBUILD.md host index and leaves unknown facts as TODOs.
It calls no model, uploads nothing,
phones home nowhere and never runs on its own. Collection uses only the local
host or SSH targets you explicitly configure. An optional `check --privacy`
uses your installed `gh` CLI to look up repository visibility when you request it.

## Quickstart

From a checkout, keep running commands from the kit directory; `--repo` selects
your separate private documentation directory. Python 3.11+ is required.

Stock macOS ships an older system Python. Start with uv (also works on Linux):

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

The installer writes to `~/.local/bin`. It may show a PATH warning if another uv
already exists; reopen your terminal and use `command -v uv` to check which one
runs. To install into a separate directory instead:

```sh
curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="$HOME/tools/uv" UV_NO_MODIFY_PATH=1 sh
export PATH="$HOME/tools/uv:$PATH"
```

See [uv installer options](https://docs.astral.sh/uv/configuration/installer/)
for installation paths and shell profile controls.

The first `uv run` downloads Python if the requested version is not available
(~30 MB). It stores managed Python under uv's data directory; set
`UV_PYTHON_INSTALL_DIR` to choose a separate directory.

Then run this local quickstart:

```sh
uv run --no-project --python 3.12 -- python -m homelab_kit init ../my-lab
uv run --no-project --python 3.12 -- python -m homelab_kit --repo ../my-lab add-host example-control --local
uv run --no-project --python 3.12 -- python -m homelab_kit --repo ../my-lab collect --dry-run
uv run --no-project --python 3.12 -- python -m homelab_kit --repo ../my-lab collect
uv run --no-project --python 3.12 -- python -m homelab_kit --repo ../my-lab fill
uv run --no-project --python 3.12 -- python -m homelab_kit --repo ../my-lab check
```

Local mode uses the OS collector on the control machine. Optional missing tools
produce warnings naming the tool (for example, `docker not installed`); accepted
captures still save. No user crontab is normal and is recorded as not present.
`partial (see warnings)` with exit 0 means accepted captures were saved, but an
optional fact is missing; read the named warnings to decide whether you need it.
A Windows custom `--file` reports `skipped by design (see warnings)`; only its
built-in hosts file is read.
Local failures suggest local tools or permissions; SSH advice is reserved for
SSH connection failures. To document a remote machine,
replace `PLACEHOLDER-linux-target` or `PLACEHOLDER-mac-target` below with your own
working SSH alias. List aliases with `awk '/^Host / {print $2}' ~/.ssh/config`
(or read that file in your editor). Set up the SSH prerequisites below first.

```sh
uv run --no-project --python 3.12 -- python -m homelab_kit --repo ../my-lab add-host example-linux --ssh PLACEHOLDER-linux-target
uv run --no-project --python 3.12 -- python -m homelab_kit --repo ../my-lab add-host example-mac --ssh PLACEHOLDER-mac-target
```

On Linux with Python 3.11+, `python3 -m homelab_kit` replaces the uv prefix.
On Windows, use PowerShell, Python 3.11+ via the `py` launcher, and the Windows
OpenSSH client for remote collection (`Get-Command ssh` checks it is installed).
Enable OpenSSH Client in Windows Optional Features if it is missing. Keep this account's
keys in `%USERPROFILE%\.ssh`. List
aliases with `Select-String '^Host ' $HOME/.ssh/config` or read the file in an editor.
Start locally; remote SSH login must work from this Windows account separately.

```powershell
py -3 -m homelab_kit init ../my-lab
py -3 -m homelab_kit --repo ../my-lab add-host example-control --local
py -3 -m homelab_kit --repo ../my-lab collect --dry-run
py -3 -m homelab_kit --repo ../my-lab collect
py -3 -m homelab_kit --repo ../my-lab fill
py -3 -m homelab_kit --repo ../my-lab check
```

Use `py -3 --version` to confirm the interpreter is new enough. With uv installed
on Windows, the same uv prefix above also works in PowerShell.

## SSH prerequisites

The kit uses the target string exactly as given. Per-host `IdentityFile`, `User`
and `ProxyJump` settings belong under a `Host` alias in `~/.ssh/config`.
Use that alias: `user@address` does not select settings under a different alias.
If `ssh` works for an alias but not `user@address`, use the alias in the kit too.

Key-based login must work with plain `ssh HOST true` from the machine running the
kit, using the same account. Configure a private key on that control machine and
an already authorized public key on the target; a key on another control machine
does not grant this one access. On first connection, verify the host fingerprint
with the owner before accepting it in an interactive SSH session. A changed host
key needs owner verification before updating known_hosts. The kit never bypasses
host-key checks: it passes `StrictHostKeyChecking=yes`, `BatchMode=yes` and
`NumberOfPasswordPrompts=0`, with closed stdin and a connection timeout of at most
10 seconds. Unknown keys fail fast: first connection, trust the host key with
`ssh HOST true` once after verifying its fingerprint with the owner. Each command
has a 10-second execution budget; process startup and cleanup can make the CLI
report an unreachable host after about 11 seconds. All commands and file reads
share a 60-second budget per host, plus startup and cleanup overhead.
Timeout cleanup kills the process tree, including
Windows child processes. No SSH multiplexing options are added.

For a Windows target using cmd, use `ssh -n HOST powershell -NoProfile -Command exit`
as the login check; `true` is a POSIX command. `-n` closes stdin, which PowerShell
over SSH needs to exit promptly. The kit already closes stdin for its own commands.
The Windows collector uses PowerShell
and does not require bash. Use a different target only when you want remote facts;
use `--local` for the control machine to avoid needing SSH into itself.

Define aliases in `~/.ssh/config` (Windows: `$HOME/.ssh/config`) with your actual
address, account and key path. This example is deliberately a placeholder:

```sshconfig
Host PLACEHOLDER-linux-target
    HostName 192.0.2.10
    User example-operator
    IdentityFile ~/.ssh/example-lab-key
    IdentitiesOnly yes
```

An alias that is neither configured nor resolvable is reported as an undefined
SSH target; replace the placeholder with a working alias. An unreachable/timeout
result means check alias, address, network and SSH port.
Authentication failed (publickey) means configure this control machine's SSH
identity and verify it is authorized. An incomplete observation saves no partial
capture; a previous capture is retained only when one exists. Failure diagnostics
show fixed reasons and fixes, never raw remote output.

For an optional installed CLI on Linux/macOS:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
```

If a venv is already active, install into that environment instead:

```sh
python3 -m pip install .
```

On Windows use `py -3 -m venv .venv` and
`.venv\Scripts\python -m pip install .`.
On Debian/Ubuntu, a missing ensurepip error means install the `python3-venv`
package if you want a venv, or use the standard-library commands above.
After installation, `homelab-kit` replaces `python3 -m homelab_kit` below.
Try a safe example without connecting to any machine:

```sh
python3 -m homelab_kit demo demo-lab
python3 -m homelab_kit --repo demo-lab check
python3 -m homelab_kit --repo demo-lab collect --dry-run
python3 -m homelab_kit --repo demo-lab fill
```

The tiny demo has two example hosts, one SSH target and one docs-only storage
device. It never connects to them. `init PATH --example` creates the same demo;
`init PATH` starts empty. Run `homelab-kit --repo PATH ...` to work on another lab.
The kit does not create a hosted repo or push changes.

## Keep it in a private git repo

Captures can include hostnames, IPs, account names and paths, including details
from crontabs, process inventories and the hosts file. Review every capture and
host.toml before committing; redact or remove details you do not want to keep.
The collecting user's home directory is abbreviated to `~` in captured text,
but this does not remove account names or host lists elsewhere in the output.

From the kit directory, screen your generated docs before staging anything:

```sh
python3 -m homelab_kit --repo ../my-lab check --strict
```

`--strict` fails on capture privacy patterns, including intentionally retained
addresses; a passing check cannot replace reading the files. Use the uv or `py -3`
prefix from the quickstart if needed. Open the named files and all other captures,
review or redact them, and run the check again. After that review, from your
generated docs directory:

```sh
git init
git add README.md AGENTS.md .gitignore lab.toml REBUILD.md hosts services network.md backups.md services.md runbooks
git commit -m "Start private lab documentation"
```

Do not commit secret values, keys, environment files, raw appliance exports,
browser profiles or unreviewed captures. Store secret locations only. Inspect
host metadata and captures for personal details before committing.

Create a **PRIVATE** remote and verify its visibility before any push. With the
GitHub CLI, this one-liner explicitly creates a private repository and pushes:

```sh
gh repo create NAME --private --source . --push
```

Confirm the command includes `--private` before running it and check the remote's
visibility afterward. To verify an existing remote before pushing, use
`gh repo view --json visibility` and confirm `PRIVATE`.
Alternatively, create a repository in GitHub's web UI, select **Private**, leave
it empty, verify its visibility, then follow its instructions to connect your
local repository and push. The kit performs none of these Git operations.

## Multiple devices

Use your SSH config alias when it selects an account or key. The `operator@192.0.2.10`
example below uses that literal target; it does not inherit another alias's
`IdentityFile`, `User` or `ProxyJump`. Replace it with your working alias when needed.

```sh
homelab-kit init my-lab
homelab-kit --repo my-lab add-host example-compute --ssh operator@192.0.2.10 --role Compute --file /etc/fstab
homelab-kit --repo my-lab add-host example-backup --ssh backup-alias --role Backup --ip 192.0.2.11
homelab-kit --repo my-lab add-host example-workstation --local --role Workstation
homelab-kit --repo my-lab add-host example-storage --docs-only --role NAS --ip 198.51.100.20 --config-export-location "Encrypted offline storage: export folder"
homelab-kit --repo my-lab add-host example-router --role Router
homelab-kit --repo my-lab add-service example-archive --host example-storage
homelab-kit --repo my-lab collect --dry-run
homelab-kit --repo my-lab collect
homelab-kit --repo my-lab collect --host example-compute
homelab-kit --repo my-lab check
```

Run `add-host` again with a **new name** for each device. An existing name is
refused with `host already exists`; its metadata and captures are preserved.
To change an existing host's SSH target, edit `hosts/<name>/host.toml`: set
`ssh_alias = "your-working-alias"` under `[reach]` and keep `transport = "ssh"`.
Then run `collect --host NAME` again. A failed rerun retains the accepted prior
capture. SSH aliases from your SSH config and `user@host` targets are accepted.
`--local` collects the control machine using its detected OS.
Host names accept up to 63 lowercase letters, digits or hyphens, starting with a letter.
`--role` accepts Compute, Backup, Workstation, NAS, Router or Storage appliance;
omit it to leave TODO. Unknown roles are refused before a host is created.
An absent `--local --file` warns during `add-host`; the host is still added so you
can correct the path or create the file before collecting.
SSH collection detects
Linux, macOS and Windows; Windows OpenSSH may use its default cmd shell, and the
kit invokes `powershell -NoProfile -Command` explicitly. macOS uses POSIX commands
compatible with /bin/sh and a zsh login shell. TrueNAS SCALE can use the Linux
collector; TrueNAS CORE (FreeBSD) and other appliances remain docs-only.
An unsupported OS gets one notice and retains any earlier capture. **Nothing is
auto-collected from non-SSH devices**, except a host explicitly selected
with `--local`. Appliance exports are location pointers: keep originals in secure
storage and manually add only reviewed, screened non-secret excerpts.

`collect` processes all hosts sequentially; `--host NAME` selects one (repeatable).
Docs-only hosts remain in the index and receive no commands. The generated
REBUILD.md index shows every host's role, IP or placeholder, collection mode and
last-collected time. Collection preserves the root README and hand-written host/service Markdown.
Expect a few seconds per SSH host (each command is its own connection). A failed connection preserves that host's previous observation and does not stop
other hosts. Refused, unreadable and unavailable files and commands are listed with warnings
in each host's observed/README.md, which also links every accepted capture;
the index shows the operating system seen in the OS capture.
A collection timestamp records an attempt, not completeness or rebuild proof.

Config `--file` and host.toml `files` entries must be literal absolute target paths
(such as `/etc/fstab` or a Windows drive-letter path), without globs or `..`;
`~/...` is also accepted and resolves against the collecting account's home on
that host. Quote it in shell commands so the control shell does not expand it.
Other relative paths and `~other-user` are refused. Local absolute paths under
the collecting user's home are stored as `~/...` in host.toml, without changing
which file is read. Paths outside that home stay absolute; remote absolute paths
are preserved so another user's home is not silently retargeted.
Windows custom paths are accepted in the inventory
but skipped during collection; only its built-in hosts file is read. Refusal
messages and observed file labels show the supplied target path, abbreviating
home/user directories as `~/...`; they never expose a resolved control path.

`check` lists a Capture privacy section and files with absolute home paths, IPs,
MACs, user@host strings or hostnames to review. These are warnings by default;
`check --strict` returns nonzero when any are found. The screen also flags account
columns in process inventories, but cannot identify every account name or label.
It summarizes `N items to fill in (run fill)`; use `check --verbose` to list
every TODO location. Fresh templates can pass with unknown facts still to fill.

Edit role, IP and export-pointer metadata in each host.toml to update the index.
Each service links its host and backups; hosts link services, network and backups.
`add-service --template local-llm` and `--template remote-browser` add optional
plain text sections. Tailscale is an optional section in network.md.

## Fill with your own agent

Run `uv run --no-project --python 3.12 -- python -m homelab_kit --repo ../my-lab fill` (alias `agent`), optionally
with `--host NAME`, and give its brief to your coding agent along with access to
your private docs directory. It prints instructions and accepted capture paths;
when none exist it says "no captures yet: run collect first" and stops.
It does not edit docs or invoke a model. The reusable
[agent skill](homelab_kit/data/fill-homelab-docs/SKILL.md) is public-neutral and bundled in the
package. The scaffold AGENTS.md points agents to the same workflow.

Have the agent fill host READMEs, network.md, services.md, backups.md and runbooks.
Each factual line cites its capture with a relative Markdown link. Owner-provided
inventory metadata may cite that host's `host.toml`; fresh generated templates
pass `check` without captures. Unknowns stay TODO; a listener does not prove a service's purpose or reachability, and a timer
name does not prove a backup succeeded. Secrets are referenced only as
`stored in <password manager entry>`. Run `check`, verify every claim against its
source, and review the draft yourself before committing to your private repo.
See [fill and provenance](docs/fill.md).

## Secrets and review

Record only **where** a secret lives, for example:
`secret: <where it lives>` (for example, password manager entry "example-admin"). Never copy a value into docs.
The path denylist refuses credential files, private keys, environment files,
wallets, browser profiles and password-manager data, including resolved paths.
The line screen refuses the **entire captured file** on the first secret-like hit,
including command output. Only its supplied source path (home abbreviated) and first flagged line number
are recorded; none of that capture is written. It checks normalized key names,
assignments, authentication forms, private-key headers and CSV-shaped rows.
Config basenames containing pass, secret, cred, token, auth, keyring or export
are refused before reading, including resolved names, with no override flag.
Raw diagnostics are never printed or saved. These checks reduce risk; they cannot
guarantee detection. Review every captured file and diff before pushing.

`check` uses the same screen across the documentation repo, summarizes TODOs
(`check --verbose` lists file/line locations), and flags handwritten claims without a valid local source. It returns
nonzero for source warnings, secret-like or unreadable content; TODOs alone are
reported without failing. Capture privacy warnings also fail with `--strict`;
they never print the matched personal values. Review captures before `git add`,
even if the check passes. It is read-only; fix the
reported content yourself. `check --privacy` warns if `gh` reports a non-private
repo; without `gh` or a successful lookup, privacy remains unknown. Collection's
`--dry-run` prints a compact host summary, makes no connections and writes nothing;
add `--verbose` to see every fixed command. Host status shows refused and unreadable
file counts or partial warnings instead of claiming a complete capture.

User review before pushing is required. Review all captured content and `git diff`
before committing or pushing to your
own private repo. Keep a password-manager recovery route outside the homelab.
See [security](SECURITY.md), [collection](docs/collection.md) and
[Handling secrets](docs/secrets.md).

## Limits (limitations)

- Live collection was verified on local Linux, SSH Linux, TrueNAS SCALE over SSH
  with the Linux collector, macOS over SSH and Windows 11 over SSH using its cmd
  shell. The final rerun accepted Mac and Windows captures without warnings;
  missing or unreadable optional Linux tools still produced warnings.
  The Python test suite was verified on 3.11 and 3.14. Running the client on a
  Windows workstation was verified through PowerShell and its native OpenSSH
  client: unreachable, authentication-denied and unknown-host-key probes failed
  promptly with reasons and fixes; read-only collection of a Linux target worked
  using the Windows account's existing SSH setup. Capture uses in-memory pipes
  that support the asynchronous writes used by native Windows OpenSSH.
  Other OS versions, TrueNAS CORE and other appliances are unverified.
- Nothing is auto-collected from devices without SSH, apart from a host
  explicitly selected with `--local`. Use docs-only hosts and reviewed excerpts
  for other devices; appliance exports remain secure-storage pointers.
- It cannot prove a rebuild works; test restores yourself.
- It has no drift reports, structured facts, readiness scores or dependency-checked
  rebuild order. Re-run collection and read `git diff`.
- The screen cannot guarantee detection of every secret. It can miss short unlabeled
  values, unfamiliar key names or formats, encoded or split keys, shell-expanded
  arguments, non-Latin homoglyphs and secrets embedded in ordinary prose.
  UUID-shaped values pass the random-string check. Confirmed bypasses include XML elements, JavaScript computed keys, two-column
  CSV and tab-delimited rows, unknown names such as pin_code, and key names split
  across lines or shell strings. The random-string heuristic requires varied character classes and high entropy,
  and skips the tool's generated documentation paths and absolute file paths, so path-shaped unlabeled values can also pass. Review
  every captured file and diff before pushing; a passing check is no guarantee.
- Conservative refusal can reject harmless assignments (for example sshd_config
  lines naming a password or key file), colon rows, CSV-shaped rows with three or more
  fields, and config basenames containing
  sensitive words. JSON output, comment lines and bracketed arrays are not treated as CSV.
  Record reviewed non-secret facts by hand instead of bypassing refusals.
- NFKC normalization and removal of invisible format characters do not decode
  JSON Unicode escapes, percent encoding, HTML entities or shell expressions.
  Race-free path validation against a changing or malicious host is not provided.
- It cannot enforce repository privacy or collect appliance exports automatically.
- Linux, macOS and Windows SSH inventories are best effort; some tools need
  permissions or may be absent. Mac collection covers sw_vers/uname, CPU/memory,
  diskutil disks, ifconfig/routes, listeners, launchd labels, application names,
  Homebrew package versions if present and hosts. Windows covers OS, CPU/memory,
  disks/volumes, adapters/addresses/routes, listeners, services, task names,
  machine-wide installed program names/versions from selected uninstall registry
  keys, and hosts. It does not export registry hives, task actions, service
  command lines, Chrome profiles or credentials. Windows custom config paths are
  skipped; only its built-in hosts file is read. Per-user/portable Windows apps
  and Mac app versions are not captured. `--local` collection detects Linux, macOS or Windows.
- A citation check verifies local source existence and screening, not whether
  it supports the claim. Headings, stock template instructions and TODO question
  lines are exempt. Agent drafts require owner review; missing facts remain TODO.
- Memory and disk free-space snapshots can produce noisy diffs. TrueNAS pools,
  datasets, shares and appliance exports need separately reviewed documentation.
- It installs no background services, schedules or auto-update tasks. Run it manually.
- SSH hosts are trusted inputs: remote programs can execute their own behavior.
  Use an unprivileged SSH account, existing host-key verification and no forwarding.

## Development

Run one test process at a time:

```sh
uv run --no-project --python 3.11 -- python -m unittest discover -s tests -q
uv run --no-project --python 3.14 -- python -m unittest discover -s tests -q
python3 -m tests.break_it
python3 -m compileall -q homelab_kit
uv run --no-project --python 3.12 --with ruff -- ruff check .
uv run --no-project --python 3.12 --with mypy -- mypy homelab_kit
uv run --no-project --python 3.12 --with build -- python -m build
```

Development-only privacy tests accept an external terms file through
`HOMELAB_KIT_DENYLIST`; release verification must set it so the test does not skip.
The package is MIT licensed, copyright TayHCode. No publication is performed here.
