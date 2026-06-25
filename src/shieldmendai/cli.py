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
    IncidentTransitionError,
    IncidentValidationError,
    NotificationValidationError,
    RepairAuthorizationError,
    RepairValidationError,
    RecoveryTransitionError,
    RecoveryValidationError,
    ScenarioError,
    ShieldMendAiError,
    UnsafeIncidentStoreError,
    UnsafeNotificationError,
    UnsafeObservationError,
    UnsafeRecoveryError,
    UnsafeRepairError,
)
from .incidents import (
    LocalIncidentStore,
    load_incident_record,
    load_retention_policy,
    load_retention_scenario,
    preview_retention,
    simulate_retention,
)
from .models import ObservationStatus, SimulatedRepairOutcome, to_primitive
from .observation import ObservationCoordinator, build_simulation_registry
from .notifications import (
    NotificationChannelType,
    NotificationSimulator,
    NotificationTemplate,
    build_simulated_notifier_registry,
    load_notification_inputs,
    load_notification_policy,
    load_notification_scenario,
    load_notification_template,
    render_notification,
    safe_notification_policy_dict,
)
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
from .recovery import (
    RecoveryController,
    calculate_backoff,
    load_recovery_policy,
    load_recovery_scenario,
    load_recovery_state,
)
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
    recovery_policy = commands.add_parser(
        "inspect-recovery-policy", help="validate and summarize a recovery policy"
    )
    recovery_policy.add_argument("policy_path")
    recovery_state = commands.add_parser(
        "inspect-recovery-state", help="validate and summarize a recovery state snapshot"
    )
    recovery_state.add_argument("state_path")
    recovery = commands.add_parser(
        "simulate-recovery", help="run deterministic simulation-only recovery control"
    )
    recovery.add_argument("config_path")
    recovery.add_argument("request_path")
    recovery.add_argument("repair_policy_path")
    recovery.add_argument("recovery_policy_path")
    recovery.add_argument("scenario_path")
    backoff = commands.add_parser(
        "calculate-backoff", help="calculate deterministic recovery backoff"
    )
    backoff.add_argument("recovery_policy_path")
    backoff.add_argument("attempt_number", type=int)
    circuit = commands.add_parser(
        "inspect-circuit", help="inspect circuit state without resetting it"
    )
    circuit.add_argument("state_path")
    commands.add_parser(
        "list-notifiers", help="list deterministic simulated notifier capabilities"
    )
    notification_policy = commands.add_parser(
        "inspect-notification-policy",
        help="validate notification routing and provider references",
    )
    notification_policy.add_argument("policy_path")
    incident = commands.add_parser(
        "inspect-incident", help="validate and summarize a sanitized incident"
    )
    incident.add_argument("incident_path")
    incident_store = commands.add_parser(
        "inspect-incident-store", help="inspect a temporary incident store"
    )
    incident_store.add_argument("store_root")
    render = commands.add_parser(
        "render-notification", help="render a sanitized notification preview"
    )
    render.add_argument("incident_path")
    render.add_argument("policy_path")
    render.add_argument("template_path")
    notification = commands.add_parser(
        "simulate-notification", help="simulate notification routing and provider results"
    )
    notification.add_argument("incident_path")
    notification.add_argument("policy_path")
    notification.add_argument("scenario_path")
    notification.add_argument("--template-path")
    retention = commands.add_parser(
        "preview-retention", help="preview retention without removing records"
    )
    retention.add_argument("store_root")
    retention.add_argument("policy_path")
    retention.add_argument("--at", default="2100-01-01T00:00:00Z")
    retention_simulation = commands.add_parser(
        "simulate-retention", help="simulate retention for generated temporary fixtures"
    )
    retention_simulation.add_argument("store_root")
    retention_simulation.add_argument("policy_path")
    retention_simulation.add_argument("scenario_path")
    return parser


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list-notifiers":
            print("SIMULATION ONLY — PRODUCTION NOTIFICATION DELIVERY IS UNAVAILABLE")
            _print_json(
                [
                    to_primitive(item)
                    for item in build_simulated_notifier_registry().capabilities()
                ]
            )
            return 0
        if args.command == "inspect-notification-policy":
            policy = load_notification_policy(args.policy_path)
            print("NOTIFICATION POLICY INSPECTION ONLY — NO NOTIFICATION SENT")
            _print_json(safe_notification_policy_dict(policy))
            return 0
        if args.command == "inspect-incident":
            incident = load_incident_record(args.incident_path)
            print("INCIDENT INSPECTION ONLY — NO NOTIFICATION SENT")
            _print_json(
                {
                    **to_primitive(incident.summarized()),
                    "evidence_references": [
                        {
                            "reference_id": item.reference_id,
                            "evidence_type": item.evidence_type,
                            "summary": item.summary,
                            "redacted": True,
                        }
                        for item in incident.evidence_references
                    ],
                }
            )
            return 0
        if args.command == "inspect-incident-store":
            print("INCIDENT STORE INSPECTION ONLY — NO RECORDS REMOVED")
            _print_json(LocalIncidentStore(args.store_root).inspect())
            return 0
        if args.command == "render-notification":
            incident, policy, template = load_notification_inputs(
                args.incident_path, args.policy_path, args.template_path
            )
            channel = next(
                (
                    item.notifier_type
                    for item in policy.channels
                    if item.enabled
                    and item.notifier_type is not NotificationChannelType.NONE
                ),
                NotificationChannelType.NONE,
            )
            message = render_notification(
                incident,
                template,
                channel,
                rendered_at=incident.updated_at,
            )
            print("MESSAGE PREVIEW ONLY — NO NOTIFICATION SENT")
            _print_json(to_primitive(message))
            return 0
        if args.command == "simulate-notification":
            incident = load_incident_record(args.incident_path)
            policy = load_notification_policy(args.policy_path)
            scenario = load_notification_scenario(args.scenario_path)
            template = (
                load_notification_template(args.template_path)
                if args.template_path
                else NotificationTemplate(
                    "1.0",
                    "default-simulation-template",
                    scenario.event_type,
                    "[{severity}] {summary}",
                    "Incident {incident_id} for {application_id}/{target_id} is {status}.",
                    2000,
                )
            )
            result = NotificationSimulator().simulate(
                incident, policy, template, scenario
            )
            print("SIMULATION ONLY — NO EXTERNAL NOTIFICATION SENT")
            _print_json(to_primitive(result))
            return result.exit_code
        if args.command == "preview-retention":
            store = LocalIncidentStore(args.store_root)
            policy = load_retention_policy(args.policy_path)
            print("RETENTION PREVIEW ONLY — NO RECORDS REMOVED")
            _print_json(to_primitive(preview_retention(store, policy, now=args.at)))
            return 0
        if args.command == "simulate-retention":
            store = LocalIncidentStore(args.store_root)
            policy = load_retention_policy(args.policy_path)
            scenario = load_retention_scenario(args.scenario_path)
            result = simulate_retention(
                store,
                policy,
                now=scenario.now,
                remove_generated_fixtures=scenario.remove_generated_fixtures,
            )
            print("RETENTION SIMULATION ONLY — NO PRODUCTION RECORDS AFFECTED")
            _print_json(to_primitive(result))
            return 0
        if args.command == "inspect-recovery-policy":
            policy = load_recovery_policy(args.policy_path)
            print("RECOVERY POLICY INSPECTION ONLY — NO RECOVERY ACTION")
            _print_json(to_primitive(policy))
            return 0
        if args.command in {"inspect-recovery-state", "inspect-circuit"}:
            state = load_recovery_state(args.state_path)
            if args.command == "inspect-circuit":
                print("CIRCUIT INSPECTION ONLY — NO AUTOMATIC RESET")
                _print_json(
                    {
                        "circuit_state": state.circuit_state.value,
                        "circuit_opened_at": state.circuit_opened_at,
                        "circuit_reset_at": state.circuit_reset_at,
                        "failure_count": len(state.failure_records),
                        "half_open_attempts": state.half_open_attempts,
                        "simulation": True,
                    }
                )
            else:
                print("RECOVERY STATE INSPECTION ONLY — NO RECOVERY ACTION")
                _print_json(state.to_safe_dict())
            return 0
        if args.command == "calculate-backoff":
            policy = load_recovery_policy(args.recovery_policy_path)
            print("DETERMINISTIC CALCULATION ONLY — NO SYSTEM CHANGES")
            _print_json(
                {
                    "attempt_number": args.attempt_number,
                    "delay_seconds": calculate_backoff(policy.backoff, args.attempt_number),
                    "strategy": policy.backoff.strategy.value,
                    "simulation": True,
                }
            )
            return 0
        if args.command == "simulate-recovery":
            config = load_config(args.config_path)
            repair_input = load_repair_input(args.request_path)
            repair_policy = load_repair_policy(args.repair_policy_path)
            context = authorization_context(config, repair_input, repair_policy)
            decision = authorize_repair(repair_input.request, context)
            if not decision.permitted:
                print("RECOVERY DENIED — NO SYSTEM CHANGES")
                _print_json(decision.to_safe_dict())
                return 2
            plan = create_repair_plan(repair_input.request, context, decision)
            recovery_policy = load_recovery_policy(args.recovery_policy_path)
            scenario = load_recovery_scenario(args.scenario_path)
            result = RecoveryController(recovery_policy).simulate(plan, scenario)
            print("SIMULATION ONLY — NO LIVE RECOVERY PERFORMED")
            _print_json(to_primitive(result))
            return result.exit_code
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
    except UnsafeRecoveryError as error:
        print(f"Unsafe or unsupported recovery: {sanitize_message(str(error))}", file=sys.stderr)
        return 4
    except UnsafeIncidentStoreError as error:
        print(f"Unsafe incident store: {sanitize_message(str(error))}", file=sys.stderr)
        return 6
    except IncidentTransitionError as error:
        print(f"Incident transition error: {sanitize_message(str(error))}", file=sys.stderr)
        return 7
    except IncidentValidationError as error:
        print(f"Incident input error: {sanitize_message(str(error))}", file=sys.stderr)
        return 5 if "checksum" in str(error).lower() else 1
    except UnsafeNotificationError as error:
        print(f"Unsafe notification operation: {sanitize_message(str(error))}", file=sys.stderr)
        return 4
    except NotificationValidationError as error:
        print(f"Notification input error: {sanitize_message(str(error))}", file=sys.stderr)
        return 1
    except RecoveryTransitionError as error:
        print(f"Recovery transition error: {sanitize_message(str(error))}", file=sys.stderr)
        return 7
    except RecoveryValidationError as error:
        print(f"Recovery input error: {sanitize_message(str(error))}", file=sys.stderr)
        return 1
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
