"""Hermetic tests and the read-only repository audit exception."""
import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def audit_git(*args: str) -> bytes | None:
    try:
        result = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True,
                                timeout=10, check=False)
        return result.stdout if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def repo_files() -> list[Path]:
    listing = audit_git("ls-files", "-co", "--exclude-standard", "-z")
    if listing is not None:
        return sorted({ROOT / name.decode() for name in listing.split(b"\0") if name})
    skip = {".git", ".venv", "build", "dist", "__pycache__", "demo-lab", "scratch"}
    result = []
    for directory, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in skip and not d.endswith(".egg-info")]
        result.extend(Path(directory) / f for f in files)
    return sorted(result)


class HermeticTestCase(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / "scratch").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "scratch")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        isolated = self.root / "empty-user-dir"
        isolated.mkdir()
        self.enterContext(patch.dict(os.environ, {"HOMELAB_KIT_NOW": "2026-01-15T10:00:00Z",
                                                "HOME": str(isolated), "USERPROFILE": str(isolated)}))
        self.enterContext(patch("socket.socket.connect", side_effect=AssertionError("Network forbidden")))
        self.enterContext(patch("socket.socket.connect_ex", side_effect=AssertionError("Network forbidden")))
        try:
            from homelab_kit import runner
        except ImportError:
            return
        self.fake = self.enterContext(patch.object(runner, "run", side_effect=AssertionError("Unexpected process")))

    def cli(self, *args: str) -> tuple[int, str, str]:
        from homelab_kit.cli import main
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main(list(args))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()


def tree_bytes(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
