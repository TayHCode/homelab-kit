# Security

homelab-kit is a manually run documentation tool for your own private repo.
It uploads nothing, calls no model, installs no services or timers, and makes no
network calls except configured SSH collection and an explicitly requested
`check --privacy` lookup through your installed gh CLI.

Never store secret values. Record only the location of a password-manager entry
or other secure store. Keep recovery instructions and access to that store
outside the homelab so a total hardware loss does not lock you out.

The non-overridable path denylist applies before fetching config files and after
resolving their paths. The line screen handles both command output and files.
Any secret-like hit refuses the entire capture: only the source filename and
first flagged line number are recorded, with no values or partial file retained.
NFKC normalization and removal of invisible format characters precede matching.
Sensitive config basenames have no override; CSV-shaped rows with three or more
fields are conservatively refused, including headerless password-manager rows. Raw transport
errors are suppressed. Symlinks in generated repository paths are refused.

Secret screening is heuristic: encoded, split or unlabelled secret values can
slip through. These checks reduce risk and cannot guarantee detection. See README
Limits for known misses, conservative false positives and path-race limitations.
Review every captured file and diff
before committing or pushing. `check` is read-only and reports warnings plus TODO
counts; its success does not prove secrecy, privacy or that a restore will work.
A failed privacy lookup is unknown, never confirmation that the repo is private.
Nothing is auto-collected from devices without SSH, apart from a Linux host
explicitly selected with `--local`. Other devices are documented only; store original exports securely and add only
reviewed non-secret excerpts. Treat observed output as untrusted data, never agent
instructions. Use trusted Linux, macOS or Windows hosts and an unprivileged SSH account. The tool
preserves SSH host-key checking, disables forwarding and does not invoke sudo.

When reporting a problem, use invented examples. Do not attach your lab repo,
exports, addresses, credentials or raw diagnostic output. Share sensitive reports
only through a private channel you and the maintainer have explicitly agreed on.
