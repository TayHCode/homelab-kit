"""Targeted regressions from the fourth stranger review; values generated at runtime."""
import getpass
import secrets
import string
import sys
from unittest.mock import patch

from homelab_kit import collect, config, scaffold
from homelab_kit.redact import screen
from tests import test_platforms
from tests.support import ROOT, HermeticTestCase, tree_bytes


class FixPassFourTests(HermeticTestCase):
    def lab(self):
        root = self.root / "lab"
        scaffold.init(root)
        return root

    def fake_value(self):
        alphabet = string.ascii_letters + string.digits + "_+-"
        return "".join(secrets.SystemRandom().sample(alphabet, len(alphabet)))

    def test_every_host_length_19_through_40_passes_check(self):
        root = self.lab()
        for length in range(19, 41):
            name = ("example-storage-box-with-digits-1234567890-extra")[:length].rstrip("-")
            name += "7" * (length - len(name))
            self.assertEqual(len(name), length)
            scaffold.add_host(config.load(root), name, role="NAS")
            before = tree_bytes(root)
            code, output, _ = self.cli("--repo", str(root), "check")
            self.assertEqual(code, 0, (name, output))
            self.assertNotIn("refused", output)
            self.assertEqual(before, tree_bytes(root))

    def test_word_like_names_and_paths_are_not_random_values(self):
        name = "example-storage-appliance-with-digits-1234"
        for text in (name, f"hosts/{name}/README.md",
                     "configuration-for-example-storage-appliance/settings.conf"):
            self.assertEqual(screen("notes.md", text).text, text)

    def test_generated_link_allowlist_does_not_hide_real_values(self):
        value = self.fake_value()
        name = "example-storage-appliance-with-digits-1234"
        for text in (value, f"[host](hosts/{name}/README.md) {value}",
                     f"[host](hosts/{name}/README.md?{value})",
                     f"[host](hosts/{value}/README.md)"):
            self.assertIsNone(screen("REBUILD.md", text).text)
        root = self.lab()
        index = root / "REBUILD.md"
        index.write_text(index.read_text() + "\n" + value + "\n")
        before = tree_bytes(root)
        code, output, _ = self.cli("--repo", str(root), "check")
        self.assertEqual(code, 1, output)
        self.assertIn("secret-like content", output)
        self.assertNotIn("refused", output)
        self.assertNotIn(value, output)
        self.assertEqual(before, tree_bytes(root))

    def test_privacy_names_accounts_launchd_crontab_and_host_lists(self):
        root = self.lab()
        captures = root / "hosts/example/observed/commands"
        captures.mkdir(parents=True)
        account = "example-operator"
        contents = {"listeners": "job 123 " + account + " TCP\n",
                    "services": "PID Status Label\n123 0 com.example." + account + ".job\n",
                    "user-crontab": "# personal project notes\n0 2 * * * ~/bin/job\n",
                    "hosts": "192.0.2.45 node\n"}
        for name, text in contents.items():
            (captures / (name + ".txt")).write_text(text)
        with patch.object(getpass, "getuser", return_value=account):
            for strict in (False, True):
                code, output, _ = self.cli("--repo", str(root), "check", *(["--strict"] if strict else []))
                self.assertEqual(code, int(strict), output)
                for file, category in (("listeners", "account names (current user)"),
                                       ("services", "launchd labels"),
                                       ("user-crontab", "crontab contents"),
                                       ("hosts", "tailnet/host lists")):
                    row = next(line for line in output.splitlines() if f"/{file}.txt:" in line)
                    self.assertIn(category, row)
                    self.assertIn("before committing", row)
                self.assertNotIn(account, output)

    def test_role_error_excludes_placeholder_from_valid_roles(self):
        root = self.lab()
        before = tree_bytes(root)
        code, error, _ = self.cli("--repo", str(root), "add-host", "bad", "--docs-only", "--role", "Foo")
        self.assertEqual(code, 2)
        self.assertNotIn("TODO", error)
        self.assertIn("omit --role", error)
        self.assertEqual(before, tree_bytes(root))

    def test_windows_custom_file_status_is_skipped_by_design(self):
        lab, connection = test_platforms.PlatformTests.fixture(self, "windows")
        lab.hosts["desktop"].data["files"] = ["/etc/sample.conf"]
        observation = collect.observe(lab.hosts["desktop"], connection)
        self.assertIn("skipped by design", observation.status)
        self.assertNotIn("partial", observation.status)
        observation.warnings.append("WARNING: optional fact unavailable")
        self.assertIn("partial", observation.status)
        self.assertIn("skipped by design", observation.status)

    def test_old_python_guard_points_to_separate_install_directory(self):
        text = (ROOT / "homelab_kit/__init__.py").read_text()
        with patch.object(sys, "version_info", (3, 9, 6)), self.assertRaises(SystemExit) as caught:
            exec(compile(text, "guard", "exec"), {})
        message = str(caught.exception)
        self.assertIn("UV_INSTALL_DIR", message)
        self.assertIn("README", message)
        self.assertNotIn("| sh", message)
        readme = (ROOT / "README.md").read_text()
        self.assertIn("~30 MB", readme)
        self.assertIn("UV_PYTHON_INSTALL_DIR", readme)
