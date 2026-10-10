"""Prepare instructions for the owner's agent, without calling one or editing prose."""
from pathlib import Path

from .config import Lab, safe_path
from .provenance import source
from .redact import screen


def brief(lab: Lab, names: list[str] | None = None) -> str:
    instructions = (Path(__file__).parent / "data/fill-homelab-docs/SKILL.md").read_text()
    lines = ["## Selected host folders\n"]
    found = False
    for host in lab.select(names):
        relative = host.path.parent.relative_to(lab.root).as_posix()
        lines.append(f"- `{relative}/README.md`")
        observed = safe_path(lab.root, host.path.parent / "observed")
        accepted = []
        for folder in ("commands", "configs"):
            directory = safe_path(lab.root, observed / folder)
            if directory.is_dir():
                for path in sorted(directory.glob("*.txt")):
                    safe_path(lab.root, path)
                    name = path.relative_to(lab.root).as_posix()
                    if screen("label.txt", name, file_path=True).text != name:
                        continue
                    if not source(lab.root, host.path.parent / "README.md", path.relative_to(host.path.parent).as_posix()):
                        continue
                    accepted.append(f"  - `{name}`")
        found = found or bool(accepted)
        lines.extend(accepted or ["  - No captures yet: run collect first; no accepted captures to fill."])
    if not found:
        return "\n".join(lines) + "\nNo captures yet: run collect first. Stop here; do not infer facts.\n"
    lines.insert(0, instructions)
    lines.append("\nRun `python3 -m homelab_kit --repo PATH check` (Windows: `py -3 -m homelab_kit`).\n")
    return "\n".join(lines)
