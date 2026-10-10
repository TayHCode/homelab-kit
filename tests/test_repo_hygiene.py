import fnmatch
import ipaddress
import math
import re
from collections import Counter

from tests.support import ROOT, HermeticTestCase, repo_files

PATTERNS = {
    "email": r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}(?![\w.-])",
    "phone": r"(?<!\w)(?:(?:\+\d{1,3}[ .-])?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}|\+\d{8,15})(?!\w)",
    "home-path": r'''(?:/ho''' + r'''me/[^/\s"'<>]+|/Us''' + r'''ers/[^/\s"'<>]+|[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s"'<>]+)''',
    "tailnet": r"\b[\w.-]+\.ts\.net\b",
    "internal-host": r"(?i)(?<![\w.-])(?:[\w-]+(?:\.[\w-]+)*\.(?:internal|local|lan|corp|home|localdomain)|[a-z][a-z-]*-\d{2})(?![\w.-]|\()",
    "private-url": r'''https?://[^/\s]+/[^\s"'<>]*\bprivate\b[^\s"'<>]*''',
    "private-key": r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    "github": r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b",
    "aws": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "api": r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{30,}|xox[baprs]-[A-Za-z0-9-]{15,})\b",
    "jwt": r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    "credential-url": r"(?:https?|postgres(?:ql)?|mysql|redis)://[^\s/:]+:[^\s/@]+@[^\s]+",
    "assigned": r'''(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token)\s*[:=]\s*["']?([^\s"',;\}\]]{8,})''',
    "bearer": r"(?i)\bBearer\s+([A-Za-z0-9._~+/-]{16,})",
    "git-remote": r"git" + "@",
}
IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]+(?:%[\w-]+)?(?![\w:])")
MAC = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")


def entropy(value: str) -> float:
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values())


def allowed_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    if address.version == 4:
        prefix = tuple(address.packed[:3])
        return prefix in {(192, 0, 2), (198, 51, 100), (203, 0, 113)} or int(address) == 0 or address == ipaddress.ip_address(bytes([127, 0, 0, 1]))
    return int(address) == 1 or address.packed[:4] == bytes([32, 1, 13, 184])


class HygieneTests(HermeticTestCase):
    def test_pattern_construction(self) -> None:
        for value in ("/ho" + "me/operator/x", "/Us" + "ers/operator/x"):
            self.assertIsNotNone(re.search(PATTERNS["home-path"], value))

    def test_repository(self) -> None:
        failures = []
        for path in repo_files():
            rel = path.relative_to(ROOT).as_posix()
            if path.is_symlink():
                failures.append((rel, 0, "symlink"))
                continue
            data = path.read_bytes()
            if b"\0" in data or len(data) > 200_000:
                failures.append((rel, 0, "binary-or-size"))
            name = path.name.lower()
            forbidden = [".env", ".env.*", "*.pem", "*.key", "credentials*"]
            forbidden += ["*." + ext for ext in "png svg pdf gz zip db jpg jpeg gif webp avif bmp ico tiff tar bz2 xz zst rar sevenz mp4 mov mp3 wav exe so dylib bin pyc pyo".split()]
            segments = re.split(r"[._-]", name)
            if any(fnmatch.fnmatch(name, pat) for pat in forbidden) or set(segments) & {"token", "tokens", "credentials"} or re.search(r"id_(?:rsa|ed25519)", name):
                failures.append((rel, 0, "filename"))
            text = rel + "\n" + data.decode("utf-8")
            for rule, pattern in PATTERNS.items():
                for match in re.finditer(pattern, text):
                    failures.append((rel, text.count("\n", 0, match.start()), rule))
            for match in IP.finditer(text):
                value = match.group()
                if value == ":" * 2 and (not match.start() or text[match.start() - 1] not in "\"'["):
                    continue
                if not allowed_ip(value):
                    failures.append((rel, text.count("\n", 0, match.start()), "ip"))
            for match in MAC.finditer(text):
                if not match.group().lower().startswith(":".join(["00", "00", "5e", "00", "53"])):
                    failures.append((rel, 0, "mac"))
            for match in re.finditer(r"(?<![\w+/=-])[A-Za-z0-9_+=-]{32,}(?![\w+/=-])", text):
                value = match.group()
                if all(re.search(p, value) for p in ("[a-z]", "[A-Z]", "[0-9]")) and not re.fullmatch(r"[0-9a-fA-F]{32,128}", value) and entropy(value) >= 4.3:
                    failures.append((rel, 0, "long-run"))
        self.assertEqual(failures, [], repr(failures))
