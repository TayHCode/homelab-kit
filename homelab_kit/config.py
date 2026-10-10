"""Minimal inventory of hosts; documentation remains plain Markdown."""
import os
import re
import tomllib
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from .errors import ConfigError
from .redact import screen

NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
ALIAS = re.compile(r"^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9._-]*$")
ROLES = ("TODO", "Compute", "Backup", "Workstation", "NAS", "Router", "Storage appliance")
SETTINGS = {"connect_timeout_seconds": 10, "command_timeout_seconds": 10, "host_timeout_seconds": 60,
            "max_output_bytes": 1048576, "max_file_bytes": 262144}


def absolute_target_path(value: str) -> bool:
    """Target syntax must not depend on the control machine's operating system."""
    path = PureWindowsPath(value) if re.match(r"^[A-Za-z]:", value) else PurePosixPath(value)
    if value.startswith("~/"):
        path = PurePosixPath("/" + value[2:])
    return path.is_absolute() and ".." not in path.parts and not any(c in value for c in "*?[]")


def stored_target_path(value: str, *, local: bool) -> str:
    """Abbreviate the local collecting account's home without changing targets."""
    home = str(Path.home())
    if local and re.match(r"^[A-Za-z]:", value) and re.match(r"^[A-Za-z]:", home):
        try:
            relative = PureWindowsPath(value).relative_to(PureWindowsPath(home))
        except ValueError:
            return value
        return "~/" + (relative.as_posix() if relative.parts else "")
    if local and (value == home or value.startswith(home + os.sep)):
        return "~/" + value[len(home):].lstrip("/\\").replace("\\", "/")
    return value


def abbreviate_homes(text: str) -> str:
    """Remove collecting-user home prefixes from accepted capture text."""
    # Screen raw text first: abbreviating a path must never hide a secret hit.
    home = str(Path.home()).rstrip("/\\")
    variants = {home, home.replace("\\", "/"), home.replace("\\", "\\\\")}

    def shortened(match: re.Match) -> str:
        suffix = match.group(1)
        return "~" + ("/" + suffix.lstrip("/\\").replace("\\\\", "/").replace("\\", "/") if suffix else "")

    tail = r"(?=[/\\]|\s|[\"'<>]|$)([/\\]+[^\s\"'<>]*)?"
    for prefix in sorted(variants, key=len, reverse=True):
        text = re.sub(re.escape(prefix) + tail, shortened, text, flags=re.I if re.match(r"^[A-Za-z]:", prefix) else 0)
    # Conventional remote home paths do not depend on the control account.
    text = re.sub(r"(?:[A-Za-z]:)?[/\\]+(?:ho" + r"me|Us" + r"ers)[/\\]+[^/\\\s\"'<>]+" + tail,
                  shortened, text, flags=re.I)
    return text


def target_label(value: str) -> str:
    """Display the supplied target path, abbreviating home/user directories."""
    home = str(Path.home())
    if value == home or value.startswith(home + os.sep):
        return "~" + value[len(home):].replace("\\", "/")
    # A remote home need not match this control account's home.
    normalized = value.replace("\\", "/")
    return re.sub(r"(?:[A-Za-z]:)?/(?:ho" + r"me|Us" + r"ers)/[^/]+", "~", normalized, flags=re.I)


def check_name(name: str, root: Path | None = None) -> None:
    if not NAME.fullmatch(name):
        raise ConfigError("name: use a lowercase letter followed by letters, digits or hyphens (63 max)")


def safe_path(root: Path, path: Path) -> Path:
    """Reject existing symlink components before reading or writing lab content."""
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise ConfigError("repository path escapes the root") from None
    current = root
    for part in ("", *relative.parts):
        current /= part
        if current.is_symlink():
            raise ConfigError("repository symlinks are refused")
    return path


def safe_text(value: str, *, file_path: bool = False) -> None:
    result = screen("input.txt", value, file_path=file_path)
    if result.text != value or any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value):
        raise ConfigError("input: secret-like values and control characters are refused")


@dataclass
class Host:
    name: str
    path: Path
    data: dict

    @property
    def kind(self) -> str:
        return str(self.data["reach"]["transport"])


@dataclass
class Lab:
    root: Path
    hosts: dict[str, Host]

    def select(self, names: list[str] | None = None) -> list[Host]:
        if names and (len(set(names)) != len(names) or any(n not in self.hosts for n in names)):
            raise ConfigError("collect: unknown or duplicate host; valid hosts: "
                              + (", ".join(self.hosts) or "none (add-host first)"))
        return [self.hosts[n] for n in names] if names else list(self.hosts.values())


def load(root: Path) -> Lab:
    root = Path(os.path.abspath(root))
    safe_path(root, root / "lab.toml")
    try:
        if tomllib.loads((root / "lab.toml").read_text(encoding="utf-8-sig")) != {"schema": 2}:
            raise ValueError
        hosts = {}
        directory = safe_path(root, root / "hosts")
        for folder in sorted(directory.iterdir()):
            check_name(folder.name)
            path = safe_path(root, folder / "host.toml")
            data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
            if set(data) != {"name", "role", "ip", "config_export", "reach", "files"}:
                raise ValueError
            if data["name"] != folder.name:
                raise ValueError
            for key in ("name", "role", "ip", "config_export"):
                if not isinstance(data[key], str):
                    raise ValueError
                safe_text(data[key])
            reach = data["reach"]
            if set(reach) != {"transport", "ssh_alias"} or reach["transport"] not in {"ssh", "local", "docs"}:
                raise ValueError
            alias = reach["ssh_alias"]
            if not isinstance(alias, str) or (reach["transport"] == "ssh" and not ALIAS.fullmatch(alias)) or (reach["transport"] != "ssh" and alias):
                raise ValueError
            if not isinstance(data["files"], list):
                raise ValueError
            for file in data["files"]:
                if not isinstance(file, str) or not absolute_target_path(file):
                    raise ValueError
                safe_text(file, file_path=True)
            hosts[folder.name] = Host(folder.name, path, data)
        return Lab(root, hosts)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise ConfigError("inventory: invalid or unreadable v2 lab/host configuration") from None
