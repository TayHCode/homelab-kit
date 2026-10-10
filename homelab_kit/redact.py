"""Conservative whole-file screen; a safety net, never a guarantee."""
import csv
import json
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass

from .neverlist import denied

MARKER = "<REDACTED: record where this lives>"  # Accept legacy location markers.
KEY = r"(?:(?<!by)pass(?:word|wd|phrase)?|pwd|pw|psk|auth|community|requirepass|masterauth|rocommunity|key|salt|hash|secret|token|credential|authorization|api[_-]?key|private[_ -]?key)"
ASSIGN = re.compile(r"(?i)\b[\w.-]*" + KEY + r'''[\w.-]*[\\"']*\s*\\?[:=]''')
AUTH = re.compile(r"(?i)\b(?:Bearer|Basic)\s+\S+|\w+://[^\s/@]+@")
DIRECTIVE = re.compile(r"(?i)^\s*[\w.-]*" + KEY + r"[\w.-]*\s+(?!(?:yes|no|true|false|on|off|none);?\s*$)[^\s:=]+;?\s*$")
VENDOR_TOKEN = re.compile(r"\b(?:A[KS]IA[0-9A-Z]{16}|eyJ[\w-]{8,}\.[\w-]{8,}\.|(?:gh[pousr]_|github_pat_|glpat-|xox[abprs]-)[\w-]{16,})")
FSTAB_ROW = re.compile(r"^\s*\S+\s+(?:/\S*|none|swap)\s+[\w.-]+\s+\S+(?:\s+\d+){0,2}\s*$")
HEADING = re.compile(r"^\s*#[^=:]*:\s*$")
UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
ARRAY_ROW = re.compile(r"^\s*[\w.-]+\s*=\s*\[.*\]\s*$")
GENERATED_PATH = re.compile(r"(?<![\w/])(?:hosts/[a-z0-9-]+/(?:README\.md|host\.toml)|services/[a-z0-9-]+\.md)(?![\w./?#+=-])")
INTERFACE_FLAGS = re.compile(r"^\s*(?:[\w.-]+:\s+flags=[0-9a-fx]+<[A-Z0-9_,]*>\s+mtu\s+\d+|(?:nd6\s+)?options=[0-9a-fx]+<[A-Z0-9_,]+>)\s*$")
SOURCE_LINK = re.compile(r"\]\((?:\.\./)*(?:hosts/[a-z0-9-]+/)?observed/(?:commands|configs)/[a-z0-9.-]+\.txt(?:#[^\s)]+)?\)")
FLAGS = re.compile(r"(?i)--[\w-]*(?:pass|key|token|secret)[\w-]*(?:=|\s+)\S+")
CLIENT_AUTH = re.compile(r"(?i)\bcurl\b.*(?:\s-u\s*|\s--user(?:=|\s+))\S+|\bmysql\b.*\s-p\S+")
HASH_ROW = re.compile(r"(?i)\w+:\$[0-9a-z]+\$")
COLON_ROW = re.compile(r"^\s*[^\s:]+:[^\s:]+:[^\s:]+\s*$")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----", re.I)
RANDOM = re.compile(r"(?<![\w])(?:[A-Za-z0-9_+/=-]{32,})(?![\w])")
POINTER = re.compile(r'''(?i)^\s*(?:[-*]\s*)?''' + KEY + r'''\s*[:=]\s*(?:<where it lives>|stored in <password manager entry>|password manager entry "[a-z0-9 -]{1,60}"|<REDACTED: record where this lives>)\s*$''')


def random_value(value: str) -> bool:
    """Require varied character classes and entropy, rather than length alone."""
    if re.fullmatch(r"[a-z]+(?:-(?:[a-z]+|[0-9]+))+", value):
        return False  # Word-separated host names, including numeric parts.
    classes = sum(bool(re.search(pattern, value)) for pattern in ("[a-z]", "[A-Z]", "[0-9]"))
    entropy = -sum((count / len(value)) * math.log2(count / len(value))
                   for count in Counter(value).values())
    return classes >= 2 and entropy >= 4.3 and not value.split("=", 1)[-1].startswith("/")


def normalized(text: str) -> str:
    # Compatibility forms and invisible format characters must not hide keys.
    return "".join(c for c in unicodedata.normalize("NFKC", text)
                   if unicodedata.category(c) != "Cf")


@dataclass
class Screen:
    text: str | None
    lines: tuple[int, ...] = ()
    path: str = ""
    reason: str = "secret-like content"

    @property
    def warning(self) -> str:
        if self.text is not None:
            return ""
        location = f", line {self.lines[0]}" if self.lines else ""
        return f"refused: {self.reason} in {self.path}{location}"


def is_json(text: str) -> bool:
    try:
        return isinstance(json.loads(text), (dict, list))
    except ValueError:
        return False


def screen(path: str, text: str, *, file_path: bool = False, listing: bool = False) -> Screen:
    """`listing` marks fixed-format command output (unit and package names, URLs)
    where long hyphenated names are expected, so the random-string check is skipped."""
    if denied("/" + path.lstrip("/")) or re.search(r"(?i)credentials?(?:\.|$)", path.rsplit("/", 1)[-1]):
        return Screen(None, path=path, reason="denied path")
    structured = is_json(text)
    for number, original in enumerate(text.splitlines(keepends=True), 1):
        line = normalized(original)
        # Exempt only exact location pointers, with no invisible additions.
        if original == line and (line.strip() == MARKER or POINTER.fullmatch(line.rstrip("\r\n"))):
            continue
        if HEADING.fullmatch(line.rstrip("\r\n")):
            continue  # a comment heading such as "# Authentication:" carries no value
        random = not file_path and not listing and any(
            random_value(m.group())
            for m in RANDOM.finditer(GENERATED_PATH.sub("", SOURCE_LINK.sub("", UUID.sub("", line)))))
        # Headerless password-manager exports cannot be identified reliably.
        # Refuse CSV-shaped rows conservatively instead of guessing column names.
        try:
            # JSON documents, comments, TOML/INI arrays and fstab rows are not password-manager rows.
            plain = structured or line.lstrip().startswith(("#", ";", "//")) or ARRAY_ROW.fullmatch(line.rstrip("\r\n")) or FSTAB_ROW.fullmatch(line.rstrip("\r\n")) or listing and INTERFACE_FLAGS.fullmatch(line.rstrip("\r\n"))
            csv_row = len(next(csv.reader([line]), [])) >= 3 if "," in line and not plain else False
        except csv.Error:
            return Screen(None, (number,), path)
        if ("\0" in line or PRIVATE_KEY.search(line) or ASSIGN.search(line) or AUTH.search(line)
                or DIRECTIVE.search(line) or FLAGS.search(line) or CLIENT_AUTH.search(line)
                or HASH_ROW.search(line) or VENDOR_TOKEN.search(line) or COLON_ROW.fullmatch(line) or csv_row or random):
            return Screen(None, (number,), path)
    return Screen(text)
