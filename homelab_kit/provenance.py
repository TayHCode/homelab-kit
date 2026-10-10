"""Structural source checks for handwritten documents; never a truth verifier."""
import os
import re
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .config import safe_path
from .errors import ConfigError
from .redact import screen

LINK = re.compile(r"\[[^\]]+\]\(([^\s)]+)\)")
TEMPLATES = Path(__file__).parent / "data/templates"


def handwritten(relative: str) -> bool:
    return (relative in {"network.md", "services.md", "backups.md"}
            or bool(re.fullmatch(r"hosts/[^/]+/README\.md", relative))
            or relative.startswith(("services/", "runbooks/")) and relative.endswith(".md"))


def template_lines(path: Path) -> set[str]:
    # Stock prompts are instructions, not asserted facts. Only exact stock lines
    # are exempt; newly added prose is always checked, even in an unfilled file.
    lines = set()
    for template in TEMPLATES.rglob("*.tmpl"):
        text = template.read_text()
        if path.name == "README.md" and path.parent.parent.name == "hosts":
            try:
                metadata = tomllib.loads((path.parent / "host.toml").read_text(encoding="utf-8-sig"))
                for key in ("name", "role", "ip", "config_export"):
                    text = text.replace("@@" + key + "@@", metadata[key])
                text = text.replace("@@mode@@", metadata["reach"]["transport"])
            except (OSError, ValueError, KeyError, TypeError):
                pass
        lines.update(text.splitlines())
    return lines


def source(root: Path, document: Path, target: str) -> bool:
    url = urlsplit(target)
    if url.scheme or url.netloc or url.query:
        return False
    # Validate the link before native Path conversion adds Windows separators.
    decoded = unquote(url.path)
    if "\\" in decoded:
        return False
    path = Path(decoded)
    if path.is_absolute() or path.drive:
        return False
    candidate = Path(os.path.abspath(document.parent / path))
    try:
        safe_path(root, candidate)
        relative = candidate.relative_to(root).as_posix()
        capture = re.fullmatch(r"hosts/[^/]+/observed/(?:commands|configs)/[^/]+\.txt", relative)
        inventory = re.fullmatch(r"hosts/[^/]+/host\.toml", relative)
        if not (capture or inventory) or not candidate.is_file() or candidate.stat().st_size > 1048576:
            return False
        from .collect import FREE_FORM
        return screen(relative, candidate.read_text(encoding="utf-8-sig"),
                      listing=bool(capture and candidate.parent.name == "commands" and candidate.stem not in FREE_FORM)).text is not None
    except (ConfigError, OSError, UnicodeError, ValueError):
        return False


def claims(root: Path, path: Path, text: str) -> list[tuple[int, str]]:
    stock = template_lines(path)
    warnings = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if (not stripped or stripped.startswith(("#", "<!--", "TODO:", "- TODO:"))
                or line in stock or re.fullmatch(r"[| :\-]+", stripped)):
            continue
        targets = LINK.findall(line)
        valid = [source(root, path, target) for target in targets]
        if not any(valid):
            warnings.append((number, "claim lacks a valid capture source"))
        elif not all(valid):
            # Navigation links are allowed alongside a real citation; only links
            # that look like citations or capture paths must themselves be valid.
            if any(("observed/" in target or target.endswith("host.toml")) and not ok
                   for target, ok in zip(targets, valid, strict=True)):
                warnings.append((number, "invalid capture source link"))
    return warnings
