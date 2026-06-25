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
    RepairAuthorizationError,
    RepairValidationError,
    ScenarioError,
    ShieldMendAiError,
    UnsafeObservationError,
    UnsafeRepairError,
)
from .models import ObservationStatus, SimulatedRepairOutcome, to_primitive
from .observation import ObservationCoordinator, build_simulation_registry
from .planner import create_plan
from .repair import (
    SimulationRepairExecutor,
    action_catalog,
    authorization_context,
    authorize_repair,
    create_repair_plan,
    load_repair_input,
    load_repair_policy,
    load_repair_scenario,
)
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
    commands.add_parser(
        "list-repair-actions", help="list typed repair actions and simulation support"
    )
    policy = commands.add_parser(
        "inspect-repair-policy", help="validate and summarize a repair policy"
    )
    policy.add_argument("policy_path")
    for command, help_text in (
        ("authorize-repair", "evaluate deny-by-default repair authorization"),
        ("plan-repair", "create an authorized simulation-only repair plan"),
    ):
        subparser = commands.add_parser(command, help=help_text)
        subparser.add_argument("config_path")
        subparser.add_argument("request_path")
        subparser.add_argument("policy_path")
    repair = commands.add_parser(
        "simulate-repair", help="run deterministic simulation-only repair execution"
    )
    repair.add_argument("config_path")
    repair.add_argument("request_path")
    repair.add_argument("policy_path")
    repair.add_argument("scenario_path")
    return parser


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list-repair-actions":
            print("SIMULATION ONLY — PRODUCTION REPAIR EXECUTION IS UNAVAILABLE")
            _print_json(action_catalog())
            return 0
        if args.command == "inspect-repair-policy":
            policy = load_repair_policy(args.policy_path)
            print("REPAIR POLICY INSPECTION ONLY — NO SYSTEM CHANGES")
            _print_json(redact(to_primitive(policy)))
            return 0
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
        if args.command in {"authorize-repair", "plan-repair", "simulate-repair"}:
            config = load_config(args.config_path)
            repair_input = load_repair_input(args.request_path)
            policy = load_repair_policy(args.policy_path)
            context = authorization_context(config, repair_input, policy)
            decision = authorize_repair(repair_input.request, context)
            if args.command == "authorize-repair":
                print("REPAIR AUTHORIZATION ONLY — NO SYSTEM CHANGES")
                _print_json(decision.to_safe_dict())
                return 0 if decision.permitted else 2
            if not decision.permitted:
                print("REPAIR DENIED — NO SYSTEM CHANGES")
                _print_json(decision.to_safe_dict())
                return 2
            plan = create_repair_plan(repair_input.request, context, decision)
            if args.command == "plan-repair":
                print("SIMULATION PLANNING ONLY — NO SYSTEM CHANGES")
                _print_json(to_primitive(plan))
                return 0
            scenario = load_repair_scenario(args.scenario_path)
            result = SimulationRepairExecutor().execute(plan, scenario)
            print("SIMULATION ONLY — NO LIVE REPAIR PERFORMED")
            _print_json(to_primitive(result))
            if result.manual_intervention_required:
                return 5
            if result.outcome is SimulatedRepairOutcome.AUTHORIZED_AND_SIMULATED_FAILURE:
                return 3
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
    except UnsafeRepairError as error:
        print(f"Unsafe or unsupported repair: {sanitize_message(str(error))}", file=sys.stderr)
        return 4
    except RepairAuthorizationError as error:
        print(f"Repair denied: {sanitize_message(str(error))}", file=sys.stderr)
        return 2
    except RepairValidationError as error:
        print(f"Repair input error: {sanitize_message(str(error))}", file=sys.stderr)
        return 1
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
