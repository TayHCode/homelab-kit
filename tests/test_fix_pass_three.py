"""Generated privacy fixtures and regressions from the third stranger review."""
import json
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from homelab_kit import check, collect, config, scaffold, transport
from homelab_kit.errors import ConfigError
from homelab_kit.runner import CommandResult
from tests.support import HermeticTestCase, tree_bytes
from tests.test_collect import FakeTransport


class FixPassThreeTests(HermeticTestCase):
    def lab(self):
        root = self.root / "lab"
        scaffold.init(root)
        scaffold.add_host(config.load(root), "example-control", direct=True)
        return config.load(root)

    def capture(self, name, text):
        lab = self.lab()
        path = lab.root / "hosts/example-control/observed/commands" / (name + ".txt")
        path.parent.mkdir(parents=True)
        path.write_text(text, encoding="utf-8")
        return lab, path

    def test_capture_abbreviates_local_home_in_commands_and_config(self):
        lab = self.lab()
        home = PurePosixPath("/opt/example-user")
        file = self.root / "app.conf"
        file.write_text("directory = " + str(home / "data") + "\n")
        host = lab.hosts["example-control"]
        # This generated transport reports Linux, even on a Windows control.
        supplied = "/etc/example.conf"
        host.data["files"] = [supplied]
        raw = ("0 2 * * * " + str(home / "bin/job") + "\n").encode()
        with patch.object(Path, "home", return_value=home):
            obs = collect.observe(host, FakeTransport(output=raw, files={supplied: file.read_bytes()}))
        for name in ("commands/user-crontab.txt", "configs/1.txt"):
            self.assertIn(b"~/", obs.files[name])
            self.assertNotIn(str(home).encode(), obs.files[name])

    def test_capture_abbreviates_remote_and_windows_home_spellings(self):
        lab = self.lab()
        paths = ["/ho" + "me/example-user/job", "/Us" + "ers/example-user/job",
                 "C:" + "\\Users\\" + "example-user\\job", "C:/" + "Users/" + "example-user/job"]
        raw = ("\n".join(paths) + "\n").encode()
        obs = collect.observe(lab.hosts["example-control"], FakeTransport(output=raw))
        captured = obs.files["commands/cpu.txt"].decode()
        self.assertEqual(captured.count("~/job"), len(paths))
        self.assertNotIn("example-user", captured)

    def test_home_replacement_does_not_rewrite_neighbor_paths(self):
        from pathlib import PurePosixPath
        home = "/opt/example-user"
        from homelab_kit.config import abbreviate_homes
        with patch.object(Path, "home", return_value=PurePosixPath(home)):
            self.assertEqual(abbreviate_homes(home + "/job " + home + "-other/job"), "~/job " + home + "-other/job")

    def test_bare_remote_homes_and_escaped_windows_json_are_abbreviated(self):
        from homelab_kit.config import abbreviate_homes
        home = "/Us" + "ers/example-user"
        self.assertEqual(abbreviate_homes(home), "~")
        windows = "C:" + "\\Users\\" + "example-user\\job"
        self.assertEqual(json.loads(abbreviate_homes(json.dumps(windows))), "~/job")

    def test_windows_local_metadata_abbreviation_handles_case_and_slashes(self):
        from pathlib import PureWindowsPath
        home = PureWindowsPath("C:" + "\\Users\\" + "example-user")
        with patch.object(Path, "home", return_value=home):
            for path in (str(home / "app.conf"), (home / "app.conf").as_posix().upper()):
                self.assertEqual(config.stored_target_path(path, local=True).lower(), "~/app.conf")
            self.assertEqual(config.stored_target_path("C:/example/app.conf", local=True), "C:/example/app.conf")

    def test_native_windows_collecting_home_uses_portable_slashes(self):
        from pathlib import PureWindowsPath
        home = PureWindowsPath("C:" + "\\Users\\" + "example-user")
        with patch.object(Path, "home", return_value=home):
            raw = str(home / "bin" / "example-job")
            self.assertEqual(config.abbreviate_homes(raw), "~/bin/example-job")
            self.assertEqual(json.loads(config.abbreviate_homes(json.dumps(raw))), "~/bin/example-job")

    def test_check_lists_privacy_files_without_values_and_strict_fails(self):
        raw = ("/ho" + "me/example-user/job\n192.0.2.45\n2001:db8::45\n"
               + ":".join(["00", "00", "5e", "00", "53", "45"]) + "\n"
               + "example-operator" + "@" + "example-node\n"
               + "example-" + "long-node-name\n")
        lab, path = self.capture("cpu", raw)
        before = tree_bytes(lab.root)
        for strict in (False, True):
            args = ["--repo", str(lab.root), "check"] + (["--strict"] if strict else [])
            code, out, _ = self.cli(*args)
            self.assertEqual(code, int(strict), out)
            self.assertIn("Capture privacy", out)
            self.assertIn(path.relative_to(lab.root).as_posix(), out)
            for category in ("absolute home paths", "IP addresses", "MAC addresses", "user@host", "hostnames"):
                self.assertIn(category, out)
            self.assertNotIn("example-user", out)
            self.assertNotIn("192.0.2.45", out)
            self.assertNotIn("example-operator", out)
        self.assertEqual(before, tree_bytes(lab.root))
        self.fake.assert_not_called()

    def test_check_safe_capture_and_fresh_docs_pass_strict(self):
        lab, _ = self.capture("cpu", "example output\nversion 999.999.999.999\n~/job\n")
        code, out, _ = self.cli("--repo", str(lab.root), "check", "--strict")
        self.assertEqual(code, 0, out)
        self.assertIn("review every capture", out)
        self.assertEqual(check.repository(lab.root, strict=True)[0], 0)

    def test_check_hostname_capture_flags_even_short_names(self):
        lab, _ = self.capture("hostname", "node\n")
        code, out, _ = self.cli("--repo", str(lab.root), "check", "--strict")
        self.assertEqual(code, 1)
        self.assertIn("hostnames", out)

    def test_check_warns_on_hosts_aliases_and_process_accounts(self):
        lab, path = self.capture("hosts", "192.0.2.45 node\n")
        (path.parent / "processes.txt").write_text("USER PID COMMAND\nexample-user 123 job\n")
        code, messages = check.repository(lab.root, strict=True)
        self.assertEqual(code, 1)
        self.assertIn("account names", "\n".join(messages))
        self.assertIn("processes.txt", "\n".join(messages))

    def test_default_secret_and_provenance_failures_still_fail(self):
        lab, _ = self.capture("cpu", "example output\n")
        (lab.root / "binary").write_bytes(b"\0")
        self.assertEqual(check.repository(lab.root)[0], 1)

    def test_add_host_stores_local_home_abbreviation_and_collect_resolves_it(self):
        lab = self.lab()
        file = Path.home() / "app.conf"
        file.write_text("port = 8080\n")
        scaffold.add_host(lab, "example-file", direct=True, files=[str(file)])
        host = config.load(lab.root).hosts["example-file"]
        self.assertEqual(host.data["files"], ["~/app.conf"])
        self.assertNotIn(str(Path.home()), host.path.read_text())
        self.assertEqual(transport.LocalTransport(config.SETTINGS).resolve(host.data["files"][0]), str(file))

    def test_home_path_validation_refuses_traversal_and_other_users(self):
        self.assertTrue(config.absolute_target_path("~/app.conf"))
        for value in ("~" + "someone/app.conf", "~/../app.conf", "~/a/*.conf", "~relative"):
            self.assertFalse(config.absolute_target_path(value))

    def test_remote_home_path_resolves_on_target_not_control(self):
        self.fake.side_effect = [CommandResult(0, ("/ho" + "me/example-user/app.conf\n").encode())] * 2
        ssh = transport.SshTransport("example-target", config.SETTINGS)
        self.assertEqual(ssh.resolve("~/app.conf"), "/ho" + "me/example-user/app.conf")
        command = self.fake.call_args_list[0].args[0][-1]
        self.assertIn("$HOME", command)
        self.assertNotIn(str(Path.home()), command)

    def test_local_optional_failure_names_tool_and_local_machine(self):
        for result in (CommandResult(127, missing_executable=True), CommandResult(42)):
            reason = transport.failure_reason(result, ssh=False, tool="docker")
            self.assertIn("docker", reason)
            self.assertIn("local", reason)
            self.assertNotIn("on the target", reason)
            self.assertNotIn("install docker", reason)

    def test_local_timeout_and_permission_failures_name_local_tool(self):
        for result in (CommandResult(1, timed_out=True),
                       CommandResult(1, stderr=b"permission denied"),
                       CommandResult(1, stderr=b"Access is denied")):
            reason = transport.failure_reason(result, ssh=False, tool="docker")
            self.assertIn("docker", reason)
            self.assertIn("local", reason)
            self.assertNotIn("on the target", reason)

    def test_capture_privacy_recognizes_common_mac_spellings(self):
        octets = ["00", "00", "5e", "00", "53", "45"]
        addresses = [":".join(octets), "-".join(octets),
                     ".".join("".join(octets[i:i + 2]) for i in range(0, 6, 2))]
        for address in addresses:
            self.assertIn("MAC addresses", check.capture_privacy(Path("addresses.txt"), address))

    def test_invalid_role_refused_before_writing_and_known_roles_accepted(self):
        lab = self.lab()
        before = tree_bytes(lab.root)
        with self.assertRaisesRegex(ConfigError, "role"):
            scaffold.add_host(lab, "bad-role", role="Foo")
        self.assertEqual(before, tree_bytes(lab.root))
        for index, role in enumerate(("Compute", "Backup", "Workstation", "NAS", "Router", "Storage appliance")):
            scaffold.add_host(config.load(lab.root), "example-role-" + str(index), role=role)

    def test_missing_local_file_warns_at_add_with_private_label(self):
        lab = self.lab()
        absent = str(Path.home() / "missing.conf")
        code, out, _ = self.cli("--repo", str(lab.root), "add-host", "example-missing", "--local", "--file", absent)
        self.assertEqual(code, 0)
        self.assertIn("WARNING", out)
        self.assertIn("local file ~/missing.conf does not exist", out)
        self.assertNotIn(str(Path.home()), out)
        self.assertIn("example-missing", config.load(lab.root).hosts)

