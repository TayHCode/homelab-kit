"""SSH, local and invented-fixture transports share one small interface."""
import fnmatch
import shlex
import time
import tomllib
from pathlib import Path, PurePosixPath
from typing import Protocol

from . import runner
from .config import ALIAS, Host
from .errors import ConfigError
from .platforms import MAC_RESOLVE
from .runner import CommandResult


class CaptureFailure(Exception):
    """A transport operation failed; no raw remote diagnostic is retained."""
    def __init__(self, unreachable: bool = False, *, operation: str = "", path: str = "", reason: str = "capture failed; check SSH prerequisites with ssh HOST true") -> None:
        self.unreachable = unreachable
        self.operation, self.path, self.reason = operation, path, reason
        super().__init__("Connection lost" if unreachable else "Capture incomplete")


class Unreadable(CaptureFailure):
    """One file could not be read (for example permissions); other captures remain valid."""


def failure_reason(result: CommandResult, *, ssh: bool = True, tool: str = "") -> str:
    """Classify in memory; return only fixed text, never diagnostic content."""
    diagnostic = (result.stderr + result.stdout).decode("utf-8", errors="replace").lower()
    if ssh and ("host key verification failed" in diagnostic or "remote host identification has changed" in diagnostic
                or ("host key" in diagnostic and "strict checking" in diagnostic)):
        return ("host key unverified: host key verification failed; first connection: trust the host key with ssh HOST true once, "
                "after verifying its fingerprint with its owner; "
                "for a changed key, confirm the change with the owner before updating known_hosts")
    if ssh and result.code == 255 and ("permission denied (" in diagnostic or "authentication failed" in diagnostic):
        return ("authentication failed (publickey); configure an SSH identity on this control machine "
                "whose public key the target already accepts; verify key-based login with ssh HOST true; "
                "if ssh works for an alias but not user@address, use the alias")
    if ssh and result.code == 255 and ("could not resolve hostname" in diagnostic or "name or service not known" in diagnostic):
        return "SSH target is not defined as an alias or resolvable as a hostname; define a Host alias in ~/.ssh/config or correct the target"
    if ssh and (result.timed_out or result.code == 255):
        return ("unreachable/timeout; check the SSH alias, target address, network and SSH port "
                "from this control machine with ssh HOST true")
    if result.too_large:
        return "capture exceeded the output limit; collect a smaller reviewed file by hand"
    if result.timed_out:
        return f"local {tool or 'command'} timed out; skip this optional fact or collect it by hand"
    if "permission denied" in diagnostic or "access is denied" in diagnostic:
        if not ssh:
            return f"permission denied for local {tool or 'command'}; check local permissions, skip this optional fact or collect a reviewed excerpt by hand"
        return "permission denied on a file or fact; use a readable file, skip this optional fact or remove its --file entry and collect a reviewed excerpt by hand"
    if "not recognized" in diagnostic and ("env" in diagnostic or "bash" in diagnostic):
        return "target is Windows without bash; use the Windows collector with powershell available on the target"
    if result.code == 127 or "not found" in diagnostic or "not recognized" in diagnostic:
        if not ssh:
            return f"{tool or 'optional tool'} not installed locally; skip this optional fact or make it available locally and collect again"
        if tool:
            return f"{tool} not installed; skip this optional fact or install {tool} on the target and collect again"
        return "command not found on the target; install the required inventory tool or collect that fact by hand"
    if not ssh:
        return f"local {tool or 'optional command'} failed; check local tools and permissions, skip this optional fact or collect it by hand"
    return "command failed on the target; skip this optional fact or collect it by hand"


def require_complete(result: CommandResult, operation: str = "", path: str = "", *, ssh: bool = True) -> None:
    if result.code or result.timed_out or result.too_large:
        raise CaptureFailure(unreachable=result.code == 255 or result.timed_out, operation=operation,
                             path=path, reason=failure_reason(result, ssh=ssh))


class Transport(Protocol):
    def describe(self, action: list[str]) -> str: ...
    def run(self, argv: list[str]) -> CommandResult: ...
    def resolve(self, path: str) -> str | None: ...
    def read(self, path: str, limit: int) -> bytes: ...
    def glob(self, directory: str, pattern: str) -> list[str]: ...


class HostBudget:
    """Share one wall-clock deadline across commands and file reads for a host."""
    def __init__(self, settings: dict) -> None:
        self.settings = settings
        self.deadline: float | None = None

    ssh = False

    def remaining(self) -> float:
        if self.deadline is None:
            self.deadline = time.monotonic() + self.settings.get("host_timeout_seconds", 60)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            reason = (
                "unreachable/timeout; total wall-clock budget for this host exhausted; "
                "check the SSH alias, target address, network and SSH port with ssh HOST true"
                if self.ssh else "local collection timed out; total budget for this host exhausted; skip optional facts or collect by hand")
            raise CaptureFailure(unreachable=self.ssh, reason=reason)
        return min(self.settings["command_timeout_seconds"], remaining)


class SshTransport(HostBudget):
    ssh = True

    def __init__(self, alias: str, settings: dict) -> None:
        if not ALIAS.fullmatch(alias):
            raise ConfigError("reach.ssh_alias: invalid alias")
        super().__init__(settings)
        self.alias = alias
        self.system = "linux"

    def argv(self, action: list[str]) -> list[str]:
        if action[0] == "powershell":
            # cmd does not understand POSIX quoting or env. Scripts are fixed
            # product code, never interpolated owner input.
            script = action[-1]
            if '"' in script or '%' in script or '\n' in script:
                raise ConfigError("unsupported PowerShell command quoting")
            remote = " ".join(action[:-1]) + ' "' + script + '"'
        else:
            remote = shlex.join(["env", "LC_ALL=C", *action])
        return ["ssh", "-T", "-a", "-x", "-o", "BatchMode=yes", "-o", "NumberOfPasswordPrompts=0",
                "-o", "StrictHostKeyChecking=yes", "-o", "ClearAllForwardings=yes", "-o",
                f"ConnectTimeout={max(1, min(10, self.settings['connect_timeout_seconds']))}", "--", self.alias,
                remote]

    def describe(self, action: list[str]) -> str:
        return shlex.join(self.argv(action))

    def execute(self, argv: list[str], limit: int) -> CommandResult:
        result = runner.run(self.argv(argv), timeout=self.remaining(), limit=limit)
        if result.missing_executable:
            raise CaptureFailure(reason="OpenSSH client missing on this control machine; install the OpenSSH client and verify ssh HOST true")
        return result

    def run(self, argv: list[str]) -> CommandResult:
        return self.execute(argv, self.settings["max_output_bytes"])

    def resolve(self, path: str) -> str | None:
        if path.startswith("~/"):
            expanded = self.run(["/bin/sh", "-c", 'printf "%s/%s\\n" "$HOME" "$1"', "home-path", path[2:]])
            require_complete(expanded, "resolve", path)
            path = expanded.stdout.decode("utf-8").strip()
            if not path.startswith("/") or "\n" in path or "\0" in path:
                raise OSError("Invalid home path")
        if self.system == "macos":
            result = self.run(["/bin/sh", "-c", MAC_RESOLVE, "resolve", path])
            if result.code == 1 and not result.timed_out and not result.too_large:
                return None
            require_complete(result, "resolve", path)
            resolved = result.stdout.decode("utf-8").strip()
            if not resolved.startswith("/") or "\n" in resolved or "\0" in resolved:
                raise OSError("Invalid resolution")
            return resolved
        result = self.run(["realpath", "-e", "--", path])
        if result.code == 1 and not result.timed_out and not result.too_large:
            # Exit 1 also means permission denied or a broken link. Only a
            # successful parent listing that lacks this directory entry proves
            # absence. Include every entry type, especially symlinks.
            # This is a POSIX target path even on a Windows control machine.
            parent = str(PurePosixPath(path).parent)
            listing = self.run(["find", "-H", parent, "-mindepth", "1", "-maxdepth", "1", "-print0"])
            require_complete(listing, "resolve", path)
            entries = listing.stdout.split(b"\0")
            if entries[-1] != b"" or any(not entry.startswith((parent.rstrip("/") + "/").encode()) for entry in entries[:-1]):
                raise CaptureFailure(operation="resolve", path=path)
            if path.encode() not in entries[:-1]:
                return None
        require_complete(result, "resolve", path)
        resolved = result.stdout.decode("utf-8").strip()
        if not resolved.startswith("/") or "\n" in resolved or "\0" in resolved:
            raise OSError("Invalid resolution")
        return resolved

    def read(self, path: str, limit: int) -> bytes:
        action = (["/bin/sh", "-c", 'head -c "$1" < "$2"', "read", str(limit + 1), path]
                  if self.system == "macos" else ["head", "-c", str(limit + 1), "--", path])
        result = self.execute(action, limit + 1)
        if result.code == 255 or result.timed_out:
            raise CaptureFailure(unreachable=result.code == 255, operation="read", path=path, reason=failure_reason(result))
        if len(result.stdout) > limit:
            return result.stdout[:limit + 1]
        if result.code and not result.too_large:
            raise Unreadable(operation="read", path=path, reason=failure_reason(result))
        require_complete(result, "read", path)
        return result.stdout

    def glob(self, directory: str, pattern: str) -> list[str]:
        result = self.run(["find", directory, "-maxdepth", "1", "-type", "f", "-name", pattern])
        require_complete(result, "list", str(Path(directory) / pattern))
        return sorted(result.stdout.decode("utf-8").splitlines())


class LocalTransport(HostBudget):

    def describe(self, action: list[str]) -> str:
        return shlex.join(["env", "LC_ALL=C", *action])

    def run(self, argv: list[str]) -> CommandResult:
        return runner.run(argv, timeout=self.remaining(), limit=self.settings["max_output_bytes"])

    def resolve(self, path: str) -> str | None:
        try:
            return str(Path(path).expanduser().resolve(strict=True))
        except FileNotFoundError:
            return None

    def read(self, path: str, limit: int) -> bytes:
        result = runner.run(["head", "-c", str(limit + 1), "--", path],
                            timeout=self.remaining(), limit=limit + 1)
        if result.timed_out:
            raise CaptureFailure(operation="read", path=path, reason=failure_reason(result, ssh=False))
        if len(result.stdout) > limit:
            return result.stdout[:limit + 1]
        if result.code and not result.too_large:
            raise Unreadable(operation="read", path=path, reason=failure_reason(result, ssh=False))
        require_complete(result, "read", path, ssh=False)
        return result.stdout

    def glob(self, directory: str, pattern: str) -> list[str]:
        return sorted(str(p) for p in Path(directory).iterdir() if p.is_file() and not p.is_symlink() and fnmatch.fnmatchcase(p.name, pattern))


class FixtureTransport:
    def __init__(self, root: Path, replacements: dict[str, str] | None = None) -> None:
        self.root = root
        self.config = tomllib.loads((root / "commands.toml").read_text())
        self.replacements = replacements or {}
        self.calls: list[tuple] = []

    def expand(self, data: bytes) -> bytes:
        for marker, value in self.replacements.items():
            data = data.replace(marker.encode(), value.encode())
        return data

    def fixture_path(self, path: str) -> Path:
        target = self.root / "files" / path.lstrip("/")
        if not target.resolve().is_relative_to((self.root / "files").resolve()):
            raise OSError("Invalid fixture path")
        return target

    def describe(self, action: list[str]) -> str:
        return "fixture: " + shlex.join(action)

    def run(self, argv: list[str]) -> CommandResult:
        self.calls.append(("run", tuple(argv)))
        entry = self.config.get("commands", {}).get(shlex.join(argv))
        if entry is None:
            return CommandResult(127)
        source = (self.root / entry["file"]).resolve()
        if not source.is_relative_to(self.root.resolve()):
            raise OSError("Invalid fixture command path")
        return CommandResult(entry.get("exit", 0), self.expand(source.read_bytes()), b"", entry.get("timed_out", False))

    def resolve(self, path: str) -> str | None:
        self.calls.append(("resolve", path))
        target = self.config.get("links", {}).get(path, path)
        return target if target != path or self.fixture_path(path).is_file() else None

    def read(self, path: str, limit: int) -> bytes:
        self.calls.append(("read", path, limit))
        return self.expand(self.fixture_path(path).read_bytes())[:limit + 1]

    def glob(self, directory: str, pattern: str) -> list[str]:
        self.calls.append(("glob", directory, pattern))
        base = self.fixture_path(directory)
        if not base.exists():
            return []
        return sorted(directory.rstrip("/") + "/" + p.name for p in base.iterdir() if p.is_file() and fnmatch.fnmatchcase(p.name, pattern))


def for_host(host: Host, settings: dict) -> Transport:
    reach = host.data["reach"]
    return LocalTransport(settings) if reach["transport"] == "local" else SshTransport(reach["ssh_alias"], settings)
