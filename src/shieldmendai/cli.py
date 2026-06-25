"""ShieldMendAi Phase 2 CLI: validation and planning only."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .config import load_config
from .errors import ShieldMendAiError
from .models import to_primitive
from .planner import create_plan
from .redaction import redact, sanitize_message


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shieldmendai",
        description="ShieldMendAi configuration and dry-run planning CLI",
    )
    parser.add_argument("--version", action="version", version=f"ShieldMendAi {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("validate-config", "validate a configuration without live operations"),
        ("plan", "show a planning-only dry-run"),
        ("show-config", "show normalized configuration with redaction"),
    ):
        subparser = commands.add_parser(command, help=help_text)
        subparser.add_argument("path")
    return parser


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.path)
        if args.command == "validate-config":
            print(f"Valid ShieldMendAi configuration: {args.path}")
            print("No live operations were performed.")
        elif args.command == "show-config":
            _print_json(redact(to_primitive(config)))
        elif args.command == "plan":
            plan = create_plan(config)
            print("ShieldMendAi DRY-RUN / PLANNING ONLY")
            print("No monitoring, network, systemd, process, notification, or repair operation was performed.")
            _print_json(redact(to_primitive(plan)))
        return 0
    except ShieldMendAiError as error:
        print(f"Configuration error: {sanitize_message(str(error))}", file=sys.stderr)
        return 2


def main() -> None:
    raise SystemExit(run())
