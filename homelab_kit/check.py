"""Read-only repository screen, TODO count and optional gh privacy warning."""
import getpass
import ipaddress
import os
import re
import shutil
from pathlib import Path

from . import runner
from .collect import FREE_FORM
from .provenance import claims, handwritten
from .redact import screen

SKIP = {".git", ".venv", "__pycache__"}
HOME_PATH = re.compile(r"(?:[A-Za-z]:)?[/\\]+(?:ho" + r"me|Us" + r"ers)[/\\]+[^/\\\s\"'<>]+", re.I)
IP_CANDIDATE = re.compile(r"(?<![\w.:])[0-9A-Fa-f:.]+(?:%[\w-]+)?(?![\w.:])")
MAC = re.compile(r"(?i)(?<![\w:.-])(?:[0-9a-f]{2}(?::[0-9a-f]{2}){5}|[0-9a-f]{2}(?:-[0-9a-f]{2}){5}|[0-9a-f]{4}(?:\.[0-9a-f]{4}){2})(?![\w:.-])")
USER_HOST = re.compile(r"(?<![\w@])[\w.-]+@[\w.-]+")
HOSTNAME = re.compile(r"(?<![\w.-])(?:[a-zA-Z][\w-]*\.)+[a-zA-Z][\w-]+(?![\w.-])|(?<![\w-])[a-zA-Z][a-zA-Z0-9-]{15,}(?![\w-])")


def capture_privacy(path: Path, text: str) -> list[str]:
    """Heuristic review categories only; never return matched private values."""
    categories = []
    if HOME_PATH.search(text):
        categories.append("absolute home paths")
    for match in IP_CANDIDATE.finditer(text):
        try:
            ipaddress.ip_address(match.group().split("%", 1)[0])
        except ValueError:
            continue
        categories.append("IP addresses")
        break
    if MAC.search(text):
        categories.append("MAC addresses")
    if USER_HOST.search(text):
        categories.append("user@host")
    hosts_entries = path.stem == "hosts" and any(line.strip() and not line.lstrip().startswith("#")
                                                and len(line.split()) > 1 for line in text.splitlines())
    if HOSTNAME.search(text) or path.stem == "hostname" and text.strip() or hosts_entries:
        categories.append("hostnames")
    if re.search(r"(?im)^\s*(?:USER|USERNAME|OWNER)\s+", text):
        categories.append("account names")
    try:
        account = getpass.getuser()
    except (KeyError, OSError):
        account = ""
    if account and re.search(r"(?<![\w-])" + re.escape(account) + r"(?![\w-])", text):
        categories.append("account names (current user)")
    if path.stem == "services" and re.search(r"(?m)^\s*PID\s+Status\s+Label\s*$", text):
        categories.append("launchd labels")
    if path.stem == "user-crontab" and text.strip():
        categories.append("crontab contents")
    if hosts_entries:
        categories.append("tailnet/host lists")
    return categories


def repository(root: Path, *, verbose: bool = False, strict: bool = False) -> tuple[int, list[str]]:
    root = Path(os.path.abspath(root))
    warnings: list[str] = []
    remaining: list[str] = []
    private_captures: list[str] = []
    todos = 0

    def visit(folder: Path) -> None:
        nonlocal todos
        for path in sorted(folder.iterdir()):
            if folder == root and path.name in SKIP:
                continue
            relative = path.relative_to(root).as_posix()
            label = relative if screen("label.txt", relative, file_path=True).text == relative else "[screened path]"
            if path.is_symlink():
                warnings.append(label + ": WARNING: repository symlink refused")
            elif path.is_dir():
                visit(path)
            elif path.is_file():
                try:
                    if path.stat().st_size > 1048576:
                        raise ValueError
                    text = path.read_text(encoding="utf-8-sig")
                    # Same policy as collection: inventories are not free-form text.
                    inventory = path.parent.name == "commands" and path.parent.parent.name == "observed" and path.stem not in FREE_FORM
                    cleaned = screen(relative, text, listing=inventory)
                    if "observed" in path.relative_to(root).parts and path.suffix == ".txt":
                        categories = capture_privacy(path, text)
                        if categories:
                            private_captures.append(label + ": WARNING: review " + ", ".join(categories) + " before committing")
                    todos += text.count("TODO")
                    remaining.extend(f"TODO: {label}:{number}" for number, line in enumerate(text.splitlines(), 1) if "TODO" in line)
                    if cleaned.warning:
                        warnings.append(label + ": WARNING: " + cleaned.warning.removeprefix("refused: ") + (f" (lines {cleaned.lines})" if cleaned.lines else ""))
                    elif handwritten(relative):
                        warnings.extend(f"{label}:{number}: WARNING: {message}" for number, message in claims(root, path, text))
                except (OSError, UnicodeError, ValueError):
                    warnings.append(label + ": WARNING: unreadable, binary or oversized file; review by hand")

    if root.is_symlink():
        return 1, ["WARNING: repository symlink refused"]
    visit(root)
    privacy_section = ["Capture privacy:"]
    if private_captures:
        privacy_section += ["WARNING: captures may contain personal details; review these files before git add or committing.",
                            *private_captures, "Use check --strict to fail on capture privacy warnings."]
    else:
        privacy_section.append("No privacy patterns found; review every capture for hostnames, account names and paths before committing.")
    return int(bool(warnings) or strict and bool(private_captures)), [
        *warnings, *privacy_section, *(remaining if verbose else []), f"{todos} items to fill in (run fill)"]


def privacy(root: Path) -> tuple[int, str]:
    if not shutil.which("gh"):
        return 0, "Privacy unknown: gh not installed; confirm your repository is private"
    remote = runner.run(["git", "-C", str(root), "remote", "get-url", "origin"])
    if remote.code or remote.too_large or remote.timed_out:
        return 0, "Privacy unknown: no origin; confirm your repository is private"
    target = remote.stdout.decode("utf-8", errors="replace").strip()
    if target.startswith("-") or screen("remote.txt", target).warning:
        return 1, "WARNING: unsafe origin refused; check privacy by hand"
    result = runner.run(["gh", "repo", "view", target, "--json", "visibility", "--jq", ".visibility"])
    if result.code or result.too_large or result.timed_out:
        return 0, "Privacy unknown: gh lookup failed; confirm your repository is private"
    if result.stdout.strip() != b"PRIVATE":
        return 1, "WARNING: repository is not private"
    return 0, "Repository visibility: private"
