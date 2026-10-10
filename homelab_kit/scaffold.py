"""Create new documentation from templates; preserve existing destinations."""
import json
from pathlib import Path

from .config import (
    ALIAS,
    ROLES,
    Lab,
    absolute_target_path,
    check_name,
    load,
    safe_path,
    safe_text,
    stored_target_path,
    target_label,
)
from .errors import ConfigError

DATA = Path(__file__).parent / "data"


def copy_templates(source: Path, target: Path, values: dict[str, str]) -> None:
    for path in sorted(source.rglob("*.tmpl")):
        rel = path.relative_to(source).with_suffix("")
        if rel.name == "gitignore":
            rel = rel.with_name(".gitignore")
        dest = target / rel
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        text = path.read_text(encoding="utf-8")
        for key, value in values.items():
            text = text.replace("@@" + key + "@@", value)
        dest.write_text(text, encoding="utf-8")


def init(target: Path, example: bool = False) -> None:
    if target.is_symlink() or (target.exists() and (not target.is_dir() or any(target.iterdir()))):
        raise ConfigError("init: destination must be absent or empty")
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.chmod(0o700)
    copy_templates(DATA / "templates/repo", target, {})
    for folder in ("hosts", "services"):
        (target / folder).mkdir(mode=0o700, exist_ok=True)
    if example:
        add_host(load(target), "example-compute", ssh="operator@192.0.2.10", role="Compute", ip="192.0.2.10")
        add_host(load(target), "example-storage", role="Storage appliance", ip="198.51.100.20",
                 config_export="Encrypted offline storage: example export folder")
        add_service(load(target), "example-archive", "example-storage")
    from .assemble import write
    write(load(target))


def add_host(lab: Lab, name: str, *, ssh: str | None = None, direct: bool = False,
             role: str = "TODO", ip: str = "TODO: IP address", config_export: str = "TODO: location only",
             files: list[str] | None = None) -> None:
    check_name(name)
    if ssh is not None and (direct or not ALIAS.fullmatch(ssh)):
        raise ConfigError("add-host: invalid SSH target or conflicting transport")
    for value in (role, ip, config_export):
        safe_text(value)
    if role not in ROLES:
        raise ConfigError("add-host: role must be one of " + ", ".join(role for role in ROLES if role != "TODO") + "; omit --role to leave a placeholder")
    for file in files or []:
        safe_text(file, file_path=True)
    if any(not absolute_target_path(file) for file in files or []):
        raise ConfigError("add-host: config files require absolute POSIX, drive-letter or ~/ paths without traversal or globs")
    target = safe_path(lab.root, lab.root / "hosts" / name)
    if target.exists():
        raise ConfigError("add-host: host already exists")
    mode = "local" if direct else "ssh" if ssh else "docs"
    values = {"name": name, "role": role, "ip": ip, "config_export": config_export, "mode": mode}
    text = (DATA / "templates/host/generic-host.md.tmpl").read_text()
    for key, value in values.items():
        text = text.replace("@@" + key + "@@", value)
    target.mkdir(mode=0o700, parents=True)
    (target / "README.md").write_text(text)
    quote = json.dumps
    config = "\n".join(f"{key} = {quote(values[key])}" for key in ("name", "role", "ip", "config_export"))
    paths = [stored_target_path(file, local=direct) for file in files or []]
    config += f"\nfiles = {quote(paths)}\n\n[reach]\ntransport = {quote(mode)}\nssh_alias = {quote(ssh or '')}\n"
    (target / "host.toml").write_text(config)
    from .assemble import write
    write(load(lab.root))
    if direct:
        for file in paths:
            if not Path(file).expanduser().exists():
                print(f"WARNING: local file {target_label(file)} does not exist; host added, check the path before collect")


def add_service(lab: Lab, name: str, host: str, template: str = "service") -> None:
    check_name(name)
    if host not in lab.hosts or template not in {"service", "local-llm", "remote-browser"}:
        raise ConfigError("add-service: unknown host or template")
    target = safe_path(lab.root, lab.root / "services" / (name + ".md"))
    host_doc = safe_path(lab.root, lab.hosts[host].path.parent / "README.md")
    if target.exists():
        raise ConfigError("add-service: service already exists")
    text = (DATA / "templates/service/service.md.tmpl").read_text()
    if template != "service":
        text += "\n" + (DATA / "templates/service" / (template + ".md.tmpl")).read_text()
    target.write_text(text.replace("@@name@@", name).replace("@@host@@", host))
    with host_doc.open("a") as stream:
        stream.write(f"\n- Service: [{name}](../../services/{name}.md) [source](host.toml)\n")
    from .assemble import write
    write(lab)


def demo(target: Path) -> None:
    init(target, example=True)
