"""Small CLI; all operations run only when requested by the user."""
import argparse
from pathlib import Path
from typing import NoReturn

from . import __version__, assemble, check, collect, config, fill, scaffold
from .errors import ConfigError


class SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # Argument errors can contain secret values; emit a fixed diagnostic.
        self.exit(2, "Invalid arguments; use --help\n")


def parser() -> argparse.ArgumentParser:
    result = SafeParser(prog="homelab-kit")
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument("--repo", type=Path, default=Path.cwd())
    commands = result.add_subparsers(dest="command", required=True, parser_class=SafeParser)
    init = commands.add_parser("init", help="Create private Markdown documentation")
    init.add_argument("path", type=Path)
    init.add_argument("--example", action="store_true")
    demo = commands.add_parser("demo", help="Create a tiny two-host example, without collection")
    demo.add_argument("path", type=Path)
    host = commands.add_parser("add-host", help="Add another host with the generic template")
    host.add_argument("name")
    mode = host.add_mutually_exclusive_group()
    mode.add_argument("--ssh", metavar="ALIAS_OR_USER_AT_HOST")
    mode.add_argument("--local", dest="direct", action="store_true")
    mode.add_argument("--docs-only", action="store_true", help="Default when no transport is given")
    host.add_argument("--role", default="TODO", help="One of: " + ", ".join(config.ROLES))
    host.add_argument("--ip", default="TODO: IP address")
    host.add_argument("--config-export-location", default="TODO: location only")
    host.add_argument("--file", action="append", default=[], help="Literal absolute or ~/ config path; repeatable")
    service = commands.add_parser("add-service")
    service.add_argument("name")
    service.add_argument("--host", required=True)
    service.add_argument("--template", choices=["service", "local-llm", "remote-browser"], default="service")
    capture = commands.add_parser("collect")
    capture.add_argument("--host", action="append")
    capture.add_argument("--dry-run", action="store_true")
    capture.add_argument("--verbose", action="store_true", help="Show every planned command in a dry-run")
    agent = commands.add_parser("fill", aliases=["agent"], help="Print a capture-grounded brief for your own agent; no model calls")
    agent.add_argument("--host", action="append")
    audit = commands.add_parser("check", help="Screen secrets and count TODOs; does not edit files")
    audit.add_argument("--privacy", action="store_true", help="Explicitly look up visibility using gh")
    audit.add_argument("--verbose", action="store_true", help="List every TODO location")
    audit.add_argument("--strict", action="store_true", help="Also fail on capture privacy warnings")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "init":
            scaffold.init(args.path, args.example)
        elif args.command == "demo":
            scaffold.demo(args.path)
        elif args.command == "check":
            code, messages = check.repository(args.repo, verbose=args.verbose, strict=args.strict)
            print("\n".join(messages))
            if args.privacy:
                privacy_code, message = check.privacy(args.repo)
                print(message)
                code = max(code, privacy_code)
            else:
                print("Keep this repository private; use check --privacy for an explicit gh lookup")
            return code
        else:
            lab = config.load(args.repo)
            if args.command == "add-host":
                scaffold.add_host(lab, args.name, ssh=args.ssh, direct=args.direct, role=args.role,
                                  ip=args.ip, config_export=args.config_export_location, files=args.file)
            elif args.command == "add-service":
                scaffold.add_service(lab, args.name, args.host, args.template)
            elif args.command in {"fill", "agent"}:
                print(fill.brief(lab, args.host), end="")
            elif args.dry_run:
                print(collect.dry_run(lab, args.host, verbose=args.verbose), end="")
            else:
                code, results = collect.run(lab, args.host)
                assemble.write(lab)
                for name, result in results.items():
                    print(f"{name}: {result.status}")
                    for warning in result.warnings:
                        print(warning)
                return code
        return 0
    except ConfigError as exc:
        print(str(exc))
        return 2
    except (OSError, ValueError, RuntimeError):
        print("Operation failed safely; raw diagnostics omitted")
        return 1
