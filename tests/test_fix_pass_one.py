"""Stranger regressions: relative repo roots, safe failures and honest status."""
import secrets
import sys
from pathlib import Path
from unittest.mock import patch

from homelab_kit import check, collect, config, fill, scaffold, transport
from homelab_kit.runner import CommandResult
from homelab_kit.runner import run as bounded_run
from tests.support import HermeticTestCase, tree_bytes
from tests.test_collect import FakeTransport


class FixPassOneTests(HermeticTestCase):
    def lab(self):
        root = self.root / "lab"
        scaffold.init(root)
        scaffold.add_host(config.load(root), "example-linux", ssh="PLACEHOLDER-linux-target")
        scaffold.add_host(config.load(root), "example-storage", role="NAS", config_export="Offline storage")
        scaffold.add_service(config.load(root), "example-archive", "example-storage")
        return config.load(root)

    def test_parent_relative_root_has_valid_inventory_and_capture_sources(self):
        self.lab()
        # Exercise the literal README --repo ../my-lab shape.
        control = self.root / "kit"
        control.mkdir()
        with patch("os.getcwd", return_value=str(control)):
            relative = Path("../lab")
            loaded = config.load(relative)
            self.assertEqual(check.repository(relative)[0], 0)
            self.assertNotIn("..", loaded.root.parts)
            collect.run(loaded, ["example-linux"], factory=lambda host: FakeTransport())
            text = fill.brief(loaded)
            self.assertIn("hosts/example-linux/observed/commands/kernel.txt", text)
            self.assertNotIn("example-linux/README.md`\n  - No captures", text)

    def test_no_captures_stops_before_agent_instructions(self):
        lab = self.lab()
        before = tree_bytes(lab.root)
        text = fill.brief(lab)
        self.assertIn("no captures yet: run collect first", text.lower())
        self.assertNotIn("1. Read", text)
        self.assertEqual(tree_bytes(lab.root), before)

    def test_mixed_brief_lists_captures_and_marks_only_empty_hosts(self):
        lab = self.lab()
        collect.run(lab, ["example-linux"], factory=lambda host: FakeTransport())
        text = fill.brief(lab)
        self.assertIn("1. Read", text)
        self.assertIn("observed/commands/kernel.txt", text)
        self.assertIn("example-storage/README.md`\n  - No captures yet", text)

    def test_reason_classifier_never_returns_raw_diagnostics(self):
        cases = [(255, b"Permission denied (publickey).", "authentication failed (publickey)"),
                 (255, b"Host key verification failed.", "host key verification failed"),
                 (255, b"Connection timed out", "unreachable/timeout"),
                 (127, b"tool: command not found", "command not found on the target"),
                 (1, b"head: Permission denied", "permission denied on a file"),
                 (1, b"'env' is not recognized", "target is Windows without bash")]
        canary = secrets.token_urlsafe(24).encode()
        for code, raw, expected in cases:
            with self.subTest(expected=expected):
                result = CommandResult(code, canary, raw + b"\n" + canary)
                reason = transport.failure_reason(result)
                self.assertIn(expected, reason)
                self.assertNotIn(canary.decode(), reason)
                if code == 255:
                    with self.assertRaises(transport.CaptureFailure) as caught:
                        transport.require_complete(result)
                    self.assertIn(expected, caught.exception.reason)

    def test_first_failure_has_one_reason_and_no_retained_claim(self):
        lab = self.lab()
        self.fake.side_effect = None
        self.fake.return_value = CommandResult(255, stderr=b"Permission denied (publickey).")
        code, out, _ = self.cli("--repo", str(lab.root), "collect", "--host", "example-linux")
        self.assertEqual(code, 1)
        self.assertIn("authentication failed (publickey)", out)
        self.assertNotIn("previous capture retained", out)
        self.assertEqual(out.count("WARNING:"), 1)

    def test_retained_claim_requires_existing_capture(self):
        lab = self.lab()
        collect.run(lab, ["example-linux"], factory=lambda host: FakeTransport())
        before = tree_bytes(lab.root / "hosts/example-linux/observed")
        self.fake.side_effect = None
        self.fake.return_value = CommandResult(255, timed_out=True)
        code, results = collect.run(lab, ["example-linux"])
        self.assertEqual(code, 1)
        self.assertIn("previous capture retained", results["example-linux"].warnings[0])
        self.assertEqual(tree_bytes(lab.root / "hosts/example-linux/observed"), before)

    def test_missing_control_client_identifies_openssh(self):
        lab = self.lab()
        self.fake.side_effect = None
        self.fake.return_value = CommandResult(127, missing_executable=True)
        code, results = collect.run(lab, ["example-linux"])
        self.assertEqual(code, 1)
        self.assertIn("OpenSSH client missing on this control machine", results["example-linux"].warnings[0])

    def test_silent_remote_command_failure_is_not_a_missing_local_client(self):
        self.fake.side_effect = None
        self.fake.return_value = CommandResult(127)
        result = transport.SshTransport("PLACEHOLDER-linux-target", config.SETTINGS).run(["uname"])
        self.assertIn("command not found on the target", transport.failure_reason(result))
        with patch("homelab_kit.runner.subprocess.Popen", side_effect=FileNotFoundError):
            self.assertTrue(bounded_run(["example-missing-program"]).missing_executable)

    def test_refused_and_unreadable_status_are_honest(self):
        lab = self.lab()
        host = lab.hosts["example-linux"]
        host.data["files"] = ["/etc/example.conf", "/etc/locked.conf"]
        class Denied(FakeTransport):
            def read(self, path, limit):
                if path.endswith("locked.conf"):
                    raise transport.Unreadable(reason="permission denied on a file; collect a reviewed excerpt by hand")
                return super().read(path, limit)
        raw = " = ".join(("password", secrets.token_urlsafe(24))).encode()
        fake = Denied(files={"/etc/example.conf": raw, "/etc/locked.conf": b"x"})
        _, results = collect.run(lab, [host.name], factory=lambda host: fake)
        self.assertEqual(results[host.name].status, "refused 1 file; unreadable 1 file")
        self.assertNotIn(raw, b"\n".join(tree_bytes(lab.root).values()))

    def test_compact_dry_run_verbose_opt_in_and_valid_host_names(self):
        lab = self.lab()
        brief = collect.dry_run(lab)
        full = collect.dry_run(lab, verbose=True)
        self.assertLess(len(brief.splitlines()), 8)
        self.assertIn("powershell", full)
        self.assertGreater(len(full), len(brief))
        self.fake.assert_not_called()
        for names in (["typo"], ["example-linux", "example-linux"]):
            with self.assertRaisesRegex(Exception, "valid hosts: example-linux, example-storage"):
                lab.select(names)

    def test_windows_without_bash_and_powershell_gets_the_os_fix(self):
        lab = self.lab()
        class NoShell(FakeTransport):
            def run(self, argv):
                return CommandResult(1, stderr=b"'env' is not recognized")
        result = collect.observe(lab.hosts["example-linux"], NoShell())
        self.assertEqual(result.code, 1)
        self.assertEqual(len(result.warnings), 1)
        self.assertIn("target is Windows without bash; use the Windows collector", result.warnings[0])

    def test_python_guard_precedes_unsupported_imports(self):
        text = (Path(__file__).parents[1] / "homelab_kit/__init__.py").read_text()
        with patch.object(sys, "version_info", (3, 9, 6)), self.assertRaises(SystemExit) as caught:
            exec(compile(text, "guard", "exec"), {})
        self.assertIn("you have 3.9.6", str(caught.exception))
        self.assertIn("uv run --no-project --python 3.12 -- python -m homelab_kit init ../my-lab", str(caught.exception))
        self.assertNotIn("Traceback", str(caught.exception))
