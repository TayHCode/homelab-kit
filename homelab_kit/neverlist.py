"""Non-overridable collection exclusions, including resolved paths."""
import fnmatch
import posixpath
import re
import unicodedata

RULES = {
    "desktop-ssh": ["*/.ssh", "%userprofile%/.ssh/*", "*/" + "users/*/.ssh/*"],
    "desktop-credentials": ["*/microsoft/credentials*", "*/microsoft/vault*", "*/microsoft/protect*", "*/keychains*"],
    "desktop-browser-profiles": ["*/google/chrome*", "*/chromium/*", "*/microsoft/edge*", "*/mozilla/firefox*", "*/safari*"],
    "registry-hives": ["*/ntuser.dat*", "*/usrclass.dat*", "*/windows/system32/config/*", "*.reg"],
    "environment-files": ["*/.env", "*/.env.*", "*.env", "*/.envrc"],
    "wallets": ["*wallet.dat", "*.wallet"],
    "system-password-hashes": ["/etc/shadow*", "/etc/gshadow*", "/etc/security/opasswd"],
    "ssh-private": ["*/ssh_host_*_key*", "*/id_rsa*", "*/id_ed25519*", "*/id_ecdsa*", "*/id_dsa*"],
    "key-material": ["*.pem", "*.key", "*.pem.bak", "*.key.bak", "*.p12", "*.pfx", "*.jks", "*.keytab", "*.gpg", "*.age", "*.ovpn", "/etc/ssl/private/*", "/etc/letsencrypt/*", "*/.gnupg/*"],
    "vpn-and-overlay-state": ["/etc/wireguard/*", "/var/lib/tailscale/*", "*/tailscaled.state"],
    "cloud-and-tool-credentials": ["*/.aws/*", "*/.config/gcloud/*", "*/.kube/config", "*/.docker/config.json", "*/rclone.conf", "*/.netrc", "*/.pgpass", "*/.my.cnf", "/run/secrets/*", "*/secrets/*", "*/.git-credentials", "*/.config/gh/hosts.yml", "*/.npmrc", "*/.pypirc", "*/.vault-token", "/etc/ppp/chap-secrets", "/etc/ppp/pap-secrets", "*/.config/sops/age/*", "*.nmconnection"],
    "browser-profiles": ["*/.mozilla/*", "*/.config/google-chrome/*", "*/.config/chromium/*", "*/Cookies", "*/Login Data*"],
    "password-managers": ["*.kdbx", "*.keyring", "*.1pux", "*.1pif", "*export*.csv", "*export*.json", "*/vaultwarden/*", "*/bitwarden/*"],
    "databases": ["*.sqlite", "*.sqlite3", "*.db", "*.mdb", "*.sql", "*.dump"],
    "logs-and-history": ["/var/log/*", "*.log", "*/.*_history", "*/.histfile"],
    "process-secrets": ["/proc/*/environ", "/proc/*/cmdline", "/proc/kcore"],
    "appliance-exports": ["*/pwenc_secret", "*freenas-v1.db*"],
    "additional-credentials": ["*/.htpasswd", "*/htpasswd", "*/passwd", "*/smbpasswd", "*/ipsec.secrets", "*/secrets", "*/auth.txt", "*/passwd.client", "*restic*password*", "*/age/keys.txt", "*/k3s.yaml", "/etc/kubernetes/*.conf"],
    "model-weights": ["*.gguf", "*.safetensors", "*.ckpt"],
}


def denied(path: str, *, sensitive_name: bool = False) -> str | None:
    path = "".join(c for c in unicodedata.normalize("NFKC", path)
                   if unicodedata.category(c) != "Cf")
    path = path.replace("\\", "/")
    normalized = posixpath.normpath(path).lower()
    if sensitive_name and re.search(r"pass|secret|cred|token|auth|keyring|export", posixpath.basename(normalized)):
        return "sensitive basename (no override)"
    if normalized.startswith("/"):
        normalized = "/" + normalized.lstrip("/")
    candidates = {path.lower(), normalized}
    for candidate in candidates:
        if "/.ssh/" in candidate:
            tail = candidate.split("/.ssh/", 1)[1]
            if "/" in tail or (tail not in {"authorized_keys", "config"} and not tail.endswith(".pub")):
                return "ssh-private"
        for rule, patterns in RULES.items():
            if any(fnmatch.fnmatchcase(candidate, pattern.lower()) for pattern in patterns):
                return rule
    return None
