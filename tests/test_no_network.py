import ast

from tests.support import ROOT, HermeticTestCase


class NetworkTests(HermeticTestCase):
    def test_isolated_user_directory(self) -> None:
        from pathlib import Path
        self.assertEqual(Path.home(), self.root / "empty-user-dir")
        self.assertEqual(list(Path.home().iterdir()), [])

    def test_static_boundary(self) -> None:
        denied = set("socket ssl http urllib ftplib smtplib xmlrpc asyncio requests httpx".split())
        for path in (ROOT / "homelab_kit").glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [n.name for n in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                    for name in names:
                        if name != "urllib.parse":  # Pure string parsing/escaping, no network I/O.
                            self.assertNotIn(name.split(".")[0], denied, str(path))
                        if name == "subprocess":
                            self.assertEqual(path.name, "runner.py")
                if isinstance(node, ast.Call):
                    self.assertFalse(any(k.arg == "shell" and isinstance(k.value, ast.Constant)
                                         and k.value.value is True for k in node.keywords))
                    if isinstance(node.func, ast.Name):
                        self.assertNotIn(node.func.id, {"eval", "exec"})
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        self.assertNotIn((node.func.value.id, node.func.attr), {("os", "system"), ("os", "popen")})
