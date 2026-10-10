"""Cross-platform capture provenance, private labels and actionable failures."""
import secrets
import sys
from pathlib import Path
from unittest.mock import patch

from homelab_kit import check, collect, config, fill, provenance, scaffold, transport
from homelab_kit.errors import ConfigError
from homelab_kit.runner import CommandResult
from tests.support import ROOT, HermeticTestCase, tree_bytes
from tests.test_collect import FakeTransport


class FixPassTwoTests(HermeticTestCase):
    def lab(self, *, direct=False):
        root = self.root / "lab"
        scaffold.init(root)
        scaffold.add_host(config.load(root), "example-control", direct=direct,
                          ssh=None if direct else "example-target")
        return config.load(root)

    def test_native_backslash_spelling_does_not_reject_forward_slash_links(self):
        lab = self.lab()
        collect.run(lab, factory=lambda host: FakeTransport())
        target = "observed/commands/kernel.txt"

        class NativeSpelling(type(Path())):
            def __str__(self):
                return super().__str__().replace("/", "\\")

        native = NativeSpelling(target)
        self.assertIn("\\", str(native))
        with patch.object(provenance, "Path", side_effect=lambda value: native if value == target else Path(value)):
            self.assertTrue(provenance.source(lab.root, lab.hosts["example-control"].path.parent / "README.md", target))
        for names in (None, ["example-control"]):
            self.assertIn("1. Read", fill.brief(lab, names))

    def test_crlf_bom_and_marker_are_independent_of_fill(self):
        lab = self.lab()
        fake = FakeTransport(output=b"\xef\xbb\xbfexample output\r\n")
        collect.run(lab, factory=lambda host: fake)
        observed = lab.hosts["example-control"].path.parent / "observed"
        (observed / "commands/kernel.txt").write_bytes(b"\xef\xbb\xbfLinux example\r\n")
        (observed / "last-collected.txt").write_bytes(b"\xef\xbb\xbf2026-01-15T10:00:00Z\r\n")
        for names in (None, ["example-control"]):
            text = fill.brief(lab, names)
            self.assertIn("observed/commands/kernel.txt", text)
            self.assertIn("observed/commands/cpu.txt", text)
        (observed / "last-collected.txt").unlink()
        self.assertIn("1. Read", fill.brief(lab))

    def test_backslash_urls_and_drive_links_stay_invalid(self):
        lab = self.lab()
        collect.run(lab, factory=lambda host: FakeTransport())
        document = lab.hosts["example-control"].path.parent / "README.md"
        for target in ("observed\\commands\\kernel.txt", "observed%5Ccommands%5Ckernel.txt",
                       "C:/observed/commands/kernel.txt", "//example.invalid/capture.txt"):
            self.assertFalse(provenance.source(lab.root, document, target))

    def test_powershell_bom_crlf_inventory_can_load_and_fill(self):
        lab = self.lab()
        collect.run(lab, factory=lambda host: FakeTransport())
        for path in (lab.root / "lab.toml", lab.hosts["example-control"].path):
            text = path.read_text(encoding="utf-8")
            path.write_bytes(b"\xef\xbb\xbf" + text.replace("\n", "\r\n").encode())
        loaded = config.load(lab.root)
        self.assertIn("1. Read", fill.brief(loaded))
        self.assertEqual(check.repository(lab.root)[0], 0)

    def test_refused_paths_are_target_labels_without_user_directories(self):
        lab = self.lab()
        home_paths = ["/ho" + "me/example-user/app.conf", "/Us" + "ers/example-user/app.conf",
                      "C:\\Users\\" + "example-user\\app.conf", str(Path.home() / "app.conf")]
        raw = " = ".join(("password", secrets.token_urlsafe(24))).encode()
        for path in home_paths:
            host = lab.hosts["example-control"]
            host.data["files"] = [path]
            fake = FakeTransport(files={path: raw})
            result = collect.observe(host, fake)
            content = "\n".join(result.warnings) + result.files["README.md"].decode()
            self.assertIn("~/app.conf", content)
            self.assertNotIn("example-user", content)
            self.assertNotIn(str(Path.home()), content)
            self.assertNotIn(raw.decode(), content)

    def test_resolved_path_is_never_used_as_a_display_label(self):
        lab = self.lab()
        supplied = "/etc/example.conf"
        resolved = "/ho" + "me/example-user/app.conf"
        host = lab.hosts["example-control"]
        host.data["files"] = [supplied]
        fake = FakeTransport(files={resolved: b"port = 8080\n"}, links={supplied: resolved})
        result = collect.observe(host, fake)
        self.assertIn("(/etc/example.conf)", result.files["README.md"].decode())
        self.assertNotIn("example-user", repr(result.files))
        self.assertIn(("read", resolved), fake.calls)

    def test_denied_windows_home_path_is_private_and_never_read(self):
        lab = self.lab()
        host = lab.hosts["example-control"]
        host.data["files"] = ["C:\\Users\\" + "example-user\\.env"]
        fake = FakeTransport()
        result = collect.observe(host, fake)
        self.assertIn("~/.env", result.warnings[0])
        self.assertNotIn("example-user", repr(result))
        self.assertFalse(any(c[0] in {"read", "resolve"} for c in fake.calls))

    def test_no_crontab_is_not_present_without_warning_or_partial_status(self):
        for direct in (False, True):
            lab = self.lab(direct=direct) if not (self.root / "lab").exists() else config.load(self.root / "lab")
            host = lab.hosts["example-control"]
            host.data["reach"]["transport"] = "local" if direct else "ssh"

            class EmptyCron(FakeTransport):
                def run(self, argv):
                    if argv[0] == "crontab":
                        return CommandResult(1, stderr=b"no crontab for example-user\r\n")
                    return super().run(argv)

            result = collect.observe(host, EmptyCron())
            self.assertEqual(result.status, "ok")
            self.assertEqual(result.warnings, [])
            self.assertIn("crontab: no crontab for this user (not present)", result.files["README.md"].decode())
            self.assertNotIn("example-user", repr(result))

    def test_missing_docker_and_permission_failure_name_the_fact_without_ssh(self):
        lab = self.lab(direct=True)

        class MissingTools(FakeTransport):
            def run(self, argv):
                if argv[0] == "docker":
                    return CommandResult(127, missing_executable=True)
                if argv[0] == "crontab":
                    return CommandResult(1, stderr=b"Permission denied")
                return super().run(argv)

        result = collect.observe(lab.hosts["example-control"], MissingTools())
        warnings = "\n".join(result.warnings)
        self.assertIn("commands/containers.txt: docker not installed", warnings)
        self.assertIn("commands/user-crontab.txt: permission denied", warnings)
        self.assertIn("skip this optional fact", warnings)
        self.assertNotIn("SSH", warnings)

    def test_local_timeout_and_unexpected_failure_never_suggest_ssh(self):
        result = CommandResult(-9, timed_out=True)
        self.assertNotIn("SSH", transport.failure_reason(result, ssh=False))
        local = transport.LocalTransport(config.SETTINGS)
        local.deadline = 0
        with self.assertRaises(transport.CaptureFailure) as caught:
            local.remaining()
        self.assertNotIn("SSH", caught.exception.reason)
        lab = self.lab(direct=True)
        fake = FakeTransport()
        with patch.object(fake, "run", side_effect=OSError):
            obs = collect.observe(lab.hosts["example-control"], fake)
        self.assertNotIn("SSH", obs.warnings[0])

    def test_auth_failure_explains_alias_settings_and_undefined_target(self):
        denied = transport.failure_reason(CommandResult(255, stderr=b"Permission denied (publickey)."))
        self.assertIn("if ssh works for an alias but not user@address, use the alias", denied)
        unresolved = transport.failure_reason(CommandResult(255, stderr=b"Could not resolve hostname example-target"))
        self.assertIn("not defined as an alias", unresolved)
        self.assertIn("~/.ssh/config", unresolved)

    def test_target_path_validation_is_control_os_independent(self):
        for path in ("/etc/example.conf", "C:\\example\\app.conf", "C:/example/app.conf"):
            self.assertTrue(config.absolute_target_path(path))
        for path in ("C:relative.conf", "C:\\example\\..\\app.conf", "/etc/../app.conf", "relative", "/etc/*.conf"):
            self.assertFalse(config.absolute_target_path(path))
        lab = self.lab()
        scaffold.add_host(lab, "example-windows", direct=True, files=["C:\\example\\app.conf"])
        self.assertEqual(config.load(lab.root).hosts["example-windows"].data["files"], ["C:\\example\\app.conf"])

    def test_missing_posix_target_uses_posix_parent_on_every_control(self):
        self.fake.side_effect = [CommandResult(1), CommandResult(0, b"/etc/other.conf\0")]
        connection = transport.SshTransport("example-target", config.SETTINGS)
        self.assertIsNone(connection.resolve("/etc/missing.conf"))
        self.assertIn("find -H /etc ", self.fake.call_args.args[0][-1])

    def test_todo_summary_is_default_and_verbose_lists_locations(self):
        lab = self.lab()
        before = tree_bytes(lab.root)
        code, out, _ = self.cli("--repo", str(lab.root), "check")
        self.assertEqual(code, 0)
        self.assertIn("items to fill in (run fill)", out)
        self.assertNotIn("TODO:", out)
        code, out, _ = self.cli("--repo", str(lab.root), "check", "--verbose")
        self.assertEqual(code, 0)
        self.assertIn("TODO:", out)
        self.assertEqual(tree_bytes(lab.root), before)
        self.assertEqual(check.repository(lab.root)[0], 0)

    def test_guard_next_step_is_literal_readme_quickstart(self):
        text = (ROOT / "homelab_kit/__init__.py").read_text()
        with patch.object(sys, "version_info", (3, 9, 6)), self.assertRaises(SystemExit) as caught:
            exec(compile(text, "guard", "exec"), {})
        next_step = str(caught.exception).split("Then run: ", 1)[1]
        self.assertIn(next_step, (ROOT / "README.md").read_text().splitlines())

    def test_repeated_host_refusal_preserves_existing_host(self):
        lab = self.lab()
        before = tree_bytes(lab.root)
        with self.assertRaisesRegex(ConfigError, "host already exists"):
            scaffold.add_host(lab, "example-control", ssh="example-other")
        self.assertEqual(tree_bytes(lab.root), before)
