from homelab_kit.neverlist import RULES, denied
from tests.support import HermeticTestCase


class NeverlistTests(HermeticTestCase):
    def test_every_pattern(self) -> None:
        for rule, patterns in RULES.items():
            for pattern in patterns:
                sample = pattern.replace("*", "sample")
                with self.subTest(rule=rule, pattern=pattern):
                    self.assertIsNotNone(denied(sample))
                    self.assertIsNotNone(denied(sample.upper()))

    def test_ssh_exceptions_and_normalization(self) -> None:
        for name in ("authorized_keys", "config", "example.pub"):
            self.assertIsNone(denied("/opt/operator/.ssh/" + name))
        for path in ("/opt/operator/.ssh/id_" + "rsa", "/etc/../etc/shadow", "/opt/operator/.ssh/sub/config", "//etc/shadow", "///etc/shadow"):
            self.assertIsNotNone(denied(path))
