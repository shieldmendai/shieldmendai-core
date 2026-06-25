"""ShieldMendAi safe configuration, planning, and simulation CLI."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .config import load_config
from .errors import (
    AdapterError,
    ConfigurationError,
    ScenarioError,
    ShieldMendAiError,
    UnsafeObservationError,
)
from .models import ObservationStatus, to_primitive
from .observation import ObservationCoordinator, build_simulation_registry
from .planner import create_plan
from .redaction import redact, sanitize_message
from .scenarios import load_scenario


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shieldmendai",
        description="ShieldMendAi configuration and simulation-only observation CLI",
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
    commands.add_parser("list-adapters", help="list simulation-only adapter capabilities")
    simulate = commands.add_parser("simulate", help="run a validated simulation scenario")
    simulate.add_argument("config_path")
    simulate.add_argument("scenario_path")
    inspect = commands.add_parser(
        "inspect-scenario", help="validate and summarize a scenario without execution"
    )
    inspect.add_argument("scenario_path")
    return parser


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list-adapters":
            registry = build_simulation_registry()
            print("SIMULATION ONLY — NO LIVE SYSTEM ACCESS")
            _print_json(redact([to_primitive(item) for item in registry.capabilities()]))
            return 0
        if args.command == "inspect-scenario":
            scenario = load_scenario(args.scenario_path)
            print("SIMULATION SCENARIO VALIDATION ONLY — NO ADAPTER EXECUTION")
            _print_json(
                {
                    "schema_version": scenario.schema_version,
                    "observed_at": scenario.observed_at,
                    "fixture_root_configured": scenario.fixture_root is not None,
                    "target_count": len(scenario.targets),
                    "targets": [
                        {
                            "target_id": item.target_id,
                            "adapter_type": item.adapter_type.value,
                            "state": item.state,
                        }
                        for item in scenario.targets
                    ],
                }
            )
            return 0
        path = args.config_path if args.command == "simulate" else args.path
        config = load_config(path)
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
        elif args.command == "simulate":
            scenario = load_scenario(args.scenario_path)
            results = ObservationCoordinator(build_simulation_registry()).run(config, scenario)
            print("SIMULATION ONLY — NO LIVE SYSTEM ACCESS")
            print("No repair or notification action was performed.")
            _print_json(
                {
                    "simulation": True,
                    "results": [
                        {
                            **to_primitive(result),
                            "findings": [finding.to_safe_dict() for finding in result.findings],
                        }
                        for result in results
                    ],
                }
            )
            statuses = {result.status for result in results}
            if ObservationStatus.OBSERVATION_ERROR in statuses:
                return 3
            if statuses - {
                ObservationStatus.HEALTHY,
                ObservationStatus.SKIPPED,
            }:
                return 2
        return 0
    except (AdapterError, UnsafeObservationError) as error:
        print(f"Unsafe or unsupported operation: {sanitize_message(str(error))}", file=sys.stderr)
        return 4
    except ConfigurationError as error:
        print(f"Configuration error: {sanitize_message(str(error))}", file=sys.stderr)
        return 1
    except ScenarioError as error:
        print(f"Scenario error: {sanitize_message(str(error))}", file=sys.stderr)
        return 1
    except ShieldMendAiError as error:
        print(f"Observation error: {sanitize_message(str(error))}", file=sys.stderr)
        return 3


def main() -> None:
    raise SystemExit(run())
