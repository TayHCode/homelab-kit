# Changelog

## Unreleased

Abbreviate home directories in captured text after screening; store local config
paths under the collecting user's home with `~`. Add capture privacy warnings
with file names and an optional `check --strict` failure. Put capture review before
git add, validate new host roles, warn about missing local files at add time, and
name failing local optional tools. Explain partial results, timeout overhead,
SSH alias keys, Windows closed stdin and an alternative uv installation directory.

Fix Windows fill after collection by validating source links before native path
conversion. Accept UTF-8 BOM and CRLF captures, abbreviate home paths in observed
labels, classify optional command failures without unrelated SSH advice, and
record absent user crontabs without warnings. Accept absolute Windows inventory
paths, summarize TODOs unless check --verbose is requested, and document alias
retargeting, private Git setup and uv installation paths.

Fix native Windows OpenSSH stalling when captured through synchronous pipes;
use in-memory pipes with asynchronous child writes and contain its process tree
in a Windows job. SSH always disables prompts, requires trusted host keys,
closes stdin and uses bounded command and per-host wall-clock deadlines.
Report unknown host keys even when only the first diagnostic line is available.

Add fixed read-only macOS and Windows SSH inventories, including explicit
PowerShell invocation for Windows' cmd shell and portable Mac config resolution.
Exclude desktop browser profiles, credential stores and registry hives; Windows
reads only its built-in hosts file and selected installed-program registry fields.
Add a dependency-free fill/agent brief and bundled agent skill; check now lists
TODO locations and validates local capture citations in handwritten documents.
Add per-OS standard-library quickstarts, optional venv guidance and Windows-safe
bounded subprocess pipe reading. Test both platforms with sanitized real samples.

Refuse whole captured files on any secret-like hit, including command output.
Broaden normalized line screening and credential-path exclusions; refuse sensitive
config basenames without an override. Identify warning sources, preserve the root
README, accept long sane config paths, and recognize mixed-case PGP/private keys.
Screen nested cache/VCS directories, escape service links, bound local file reads,
reject control characters in metadata, and create init directories with mode 0700.
Avoid echoing remote resolved names and refuse CSV parser failures.
Document remaining screening gaps and require user review before pushing.
Found by a live run on Linux, macOS, Windows and TrueNAS hosts: one unreadable
config file no longer discards a host's whole capture; unsupported SSH hosts get a
single notice; JSON output, comment lines and headings, bracketed arrays, fstab rows, "bypass" and boolean
sshd-style directives are no longer refused as secrets; machine-generated inventories skip
the random-string check, UUIDs are not random tokens; common cloud and VCS token shapes are refused; the index
shows the observed OS and observed/README.md links every capture.

## 0.2.0

Simplify the existing collector and scaffold to raw screened output and plain
Markdown. Support multiple SSH, local and docs-only hosts with one generic host
template. Replace the structured rebuild plan with a host index, keep secret
locations only, and reduce the demo to two hosts. Remove parsers, drift/readiness,
fingerprints and approvals, per-device forms and automated recovery tooling.
