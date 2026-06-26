"""ShieldMendAi safe configuration, planning, and simulation CLI."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .config import load_config
from .dedicated_canary import (
    default_canary_config,
    install_canary_package,
    install_offline_runtime,
    load_canary_config,
    observe_demo_health,
    render_canary_systemd_units,
    rollback_canary_package,
    safe_canary_dict,
    service_user_ownership_plan,
    verify_canary_systemd_fixture,
)
from .errors import (
    AdapterError,
    ConfigurationError,
    IncidentTransitionError,
    IncidentValidationError,
    InstallationConflictError,
    InstallationValidationError,
    NotificationValidationError,
    PilotPolicyDeniedError,
    PilotValidationError,
    RepairAuthorizationError,
    RepairValidationError,
    RecoveryTransitionError,
    RecoveryValidationError,
    ScenarioError,
    ShieldMendAiError,
    UnsafeIncidentStoreError,
    UnsafeNotificationError,
    UnsafeObservationError,
    UnsafePilotError,
    UnsafeRecoveryError,
    UnsafeRepairError,
    UnsafeSandboxError,
)
from .installation import (
    inspect_installation,
    load_installation_manifest,
    load_installation_plan,
    plan_uninstall,
    render_systemd_units,
    safe_installation_dict,
    simulate_install,
    simulate_uninstall,
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
from .linux_pilot import (
    LinuxPilotController,
    load_pilot_configuration,
    load_pilot_policy,
    load_pilot_scenario,
    observer_capability_catalog,
    safe_pilot_dict,
)
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
    installation_plan = commands.add_parser(
        "inspect-installation-plan",
        help="validate a sandbox installation plan without host changes",
    )
    installation_plan.add_argument("plan_path")
    plan_install = commands.add_parser(
        "plan-install", help="show a sandbox installation plan without writing files"
    )
    plan_install.add_argument("config_path")
    install = commands.add_parser(
        "simulate-install", help="write a deterministic temporary-root sandbox installation"
    )
    install.add_argument("config_path")
    install.add_argument("sandbox_root")
    inspect_install = commands.add_parser(
        "inspect-installation", help="validate a sandbox installation manifest and files"
    )
    inspect_install.add_argument("sandbox_root")
    uninstall_preview = commands.add_parser(
        "preview-uninstall", help="preview fixture removal without deleting anything"
    )
    uninstall_preview.add_argument("sandbox_root")
    uninstall = commands.add_parser(
        "simulate-uninstall", help="remove only manifest-recorded temporary fixtures"
    )
    uninstall.add_argument("sandbox_root")
    uninstall.add_argument(
        "--remove-generated-fixtures",
        action="store_true",
        help="explicitly authorize removal of recorded temporary fixture files",
    )
    units = commands.add_parser(
        "render-systemd-units", help="render least-privilege unit templates without installing them"
    )
    units.add_argument("config_path")
    pilot_policy = commands.add_parser(
        "inspect-pilot-policy", help="validate a local-only read-only pilot policy"
    )
    pilot_policy.add_argument("policy_path")
    commands.add_parser(
        "list-linux-observers", help="list fixture and disabled production observer capabilities"
    )
    pilot = commands.add_parser(
        "simulate-linux-pilot", help="run one fixture-backed read-only observation cycle"
    )
    pilot.add_argument("config_path")
    pilot.add_argument("policy_path")
    pilot.add_argument("scenario_path")
    pilot.add_argument("sandbox_root")
    canary_config = commands.add_parser(
        "inspect-canary-config", help="validate the dedicated-server canary configuration"
    )
    canary_config.add_argument("config_path")
    commands.add_parser(
        "render-canary-systemd-units",
        help="render dedicated canary systemd units without installing them",
    )
    commands.add_parser(
        "show-canary-service-user-plan",
        help="show the reviewed canary service user and ownership plan",
    )
    systemd_fixture = commands.add_parser(
        "verify-canary-systemd-fixture",
        help="statically verify a complete temporary-root canary systemd fixture",
    )
    systemd_fixture.add_argument("root")
    runtime_preview = commands.add_parser(
        "canary-runtime-install-preview",
        help="preview isolated offline runtime installation without writing files",
    )
    runtime_preview.add_argument("wheel_path")
    runtime_preview.add_argument("--runtime-path", default="/opt/shieldmendai/venv")
    runtime_preview.add_argument("--expected-version")
    runtime_preview.add_argument("--expected-sha256")
    runtime_preview.add_argument("--live-reviewed", action="store_true")
    runtime_apply = commands.add_parser(
        "canary-runtime-install-apply",
        help="apply isolated offline runtime installation from a local wheel",
    )
    runtime_apply.add_argument("wheel_path")
    runtime_apply.add_argument("--runtime-path", default="/opt/shieldmendai/venv")
    runtime_apply.add_argument("--expected-version")
    runtime_apply.add_argument("--expected-sha256")
    runtime_apply.add_argument("--apply", action="store_true")
    runtime_apply.add_argument("--live-reviewed", action="store_true")
    canary_preview = commands.add_parser(
        "canary-install-preview", help="preview dedicated canary installation without writing files"
    )
    canary_preview.add_argument("root")
    canary_preview.add_argument("--config-path")
    canary_preview.add_argument("--actual-hostname")
    canary_preview.add_argument("--canary-identity")
    canary_preview.add_argument("--live-reviewed", action="store_true")
    canary_apply = commands.add_parser(
        "canary-install-apply", help="apply dedicated canary package to an explicit reviewed root"
    )
    canary_apply.add_argument("root")
    canary_apply.add_argument("--config-path")
    canary_apply.add_argument("--actual-hostname")
    canary_apply.add_argument("--canary-identity")
    canary_apply.add_argument("--apply", action="store_true")
    canary_apply.add_argument("--live-reviewed", action="store_true")
    canary_observe = commands.add_parser(
        "canary-observe", help="run one read-only dedicated canary observation cycle"
    )
    canary_observe.add_argument("root")
    canary_observe.add_argument("--config-path")
    canary_observe.add_argument("--observed-at", default="2026-06-26T00:00:00Z")
    canary_observe.add_argument("--live-reviewed", action="store_true")
    canary_rollback_preview = commands.add_parser(
        "canary-rollback-preview", help="preview dedicated canary rollback without removing files"
    )
    canary_rollback_preview.add_argument("root")
    canary_rollback_preview.add_argument("--live-reviewed", action="store_true")
    canary_rollback_apply = commands.add_parser(
        "canary-rollback-apply", help="apply dedicated canary rollback for manifest-owned files only"
    )
    canary_rollback_apply.add_argument("root")
    canary_rollback_apply.add_argument("--apply", action="store_true")
    canary_rollback_apply.add_argument("--live-reviewed", action="store_true")
    return parser


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command in {"inspect-installation-plan", "plan-install"}:
            path = args.plan_path if args.command == "inspect-installation-plan" else args.config_path
            plan = load_installation_plan(path)
            print("INSTALLATION PLAN ONLY — NO HOST CHANGES")
            _print_json(safe_installation_dict(plan))
            return 0
        if args.command == "simulate-install":
            plan = load_installation_plan(args.config_path)
            result = simulate_install(plan, args.sandbox_root)
            print("SANDBOX INSTALLATION ONLY — NO PRODUCTION INSTALLATION")
            _print_json(safe_installation_dict(result))
            return 0
        if args.command == "inspect-installation":
            manifest = load_installation_manifest(args.sandbox_root)
            validation = inspect_installation(args.sandbox_root)
            print("SANDBOX INSTALLATION INSPECTION ONLY — NO HOST CHANGES")
            _print_json(
                {
                    "manifest": safe_installation_dict(manifest),
                    "validation": safe_installation_dict(validation),
                }
            )
            return 0 if validation.valid else 5
        if args.command == "preview-uninstall":
            print("UNINSTALL PREVIEW ONLY — NOTHING REMOVED")
            _print_json(safe_installation_dict(plan_uninstall(args.sandbox_root)))
            return 0
        if args.command == "simulate-uninstall":
            result = simulate_uninstall(
                args.sandbox_root,
                preview_only=False,
                remove_generated_fixtures=args.remove_generated_fixtures,
            )
            print("SANDBOX UNINSTALLATION ONLY — NO PRODUCTION FILES AFFECTED")
            _print_json(safe_installation_dict(result))
            return 0
        if args.command == "render-systemd-units":
            load_installation_plan(args.config_path)
            print("SYSTEMD TEMPLATE PREVIEW ONLY — UNITS NOT INSTALLED")
            _print_json(render_systemd_units())
            return 0
        if args.command == "inspect-pilot-policy":
            print("READ-ONLY PILOT POLICY INSPECTION — NO LIVE SYSTEM OBSERVED")
            _print_json(safe_pilot_dict(load_pilot_policy(args.policy_path)))
            return 0
        if args.command == "list-linux-observers":
            print("READ-ONLY OBSERVER CAPABILITIES — PRODUCTION ADAPTERS DISABLED")
            _print_json(safe_pilot_dict(observer_capability_catalog()))
            return 0
        if args.command == "simulate-linux-pilot":
            result = LinuxPilotController().run_cycle(
                load_pilot_configuration(args.config_path),
                load_pilot_policy(args.policy_path),
                load_pilot_scenario(args.scenario_path),
                args.sandbox_root,
            )
            print("READ-ONLY PILOT SIMULATION — NO LIVE SYSTEM OBSERVED")
            _print_json(
                {
                    **safe_pilot_dict(result),
                    "findings": [item.to_safe_dict() for item in result.findings],
                }
            )
            return result.exit_code
        if args.command == "inspect-canary-config":
            print("VERIFICATION ONLY — DEDICATED CANARY CONFIGURATION")
            _print_json(safe_canary_dict(load_canary_config(args.config_path)))
            return 0
        if args.command == "render-canary-systemd-units":
            print("PREVIEW ONLY — DEDICATED CANARY SYSTEMD UNITS NOT INSTALLED")
            _print_json(render_canary_systemd_units())
            return 0
        if args.command == "show-canary-service-user-plan":
            print("PREVIEW ONLY — SERVICE USER AND OWNERSHIP COMMANDS NOT RUN")
            _print_json(safe_canary_dict(service_user_ownership_plan()))
            return 0
        if args.command == "verify-canary-systemd-fixture":
            print("STATIC SYSTEMD FIXTURE VERIFICATION — NO SYSTEMD OPERATION")
            result = verify_canary_systemd_fixture(args.root)
            _print_json(safe_canary_dict(result))
            return 0 if result.valid else 5
        if args.command in {"canary-runtime-install-preview", "canary-runtime-install-apply"}:
            if args.command == "canary-runtime-install-apply" and not args.apply:
                raise InstallationValidationError("runtime installation apply requires explicit --apply")
            result = install_offline_runtime(
                args.wheel_path,
                args.runtime_path,
                apply=args.command == "canary-runtime-install-apply",
                expected_version=args.expected_version or __version__,
                expected_sha256=args.expected_sha256,
                live_reviewed=args.live_reviewed,
            )
            print(
                "RUNTIME INSTALLATION APPLY — LOCAL WHEEL INSTALLED OFFLINE"
                if args.command == "canary-runtime-install-apply"
                else "PREVIEW ONLY — RUNTIME INSTALLATION CHANGES NOT WRITTEN"
            )
            _print_json(safe_canary_dict(result))
            return 0
        if args.command in {"canary-install-preview", "canary-install-apply"}:
            if args.command == "canary-install-apply" and not args.apply:
                raise InstallationValidationError("installation apply requires explicit --apply")
            config = load_canary_config(args.config_path) if args.config_path else default_canary_config()
            result = install_canary_package(
                config,
                args.root,
                apply=args.command == "canary-install-apply",
                actual_hostname=args.actual_hostname,
                canary_identity=args.canary_identity,
                live_reviewed=args.live_reviewed,
            )
            print(
                "INSTALLATION APPLY — DEDICATED CANARY PACKAGE WRITTEN"
                if args.command == "canary-install-apply"
                else "PREVIEW ONLY — DEDICATED CANARY INSTALLATION CHANGES NOT WRITTEN"
            )
            _print_json(safe_canary_dict(result))
            return 0
        if args.command == "canary-observe":
            config = load_canary_config(args.config_path) if args.config_path else default_canary_config()
            result = observe_demo_health(
                config,
                args.root,
                observed_at=args.observed_at,
                live_reviewed=args.live_reviewed,
            )
            print("READ-ONLY CANARY OBSERVATION — NO REPAIR OR NOTIFICATION")
            _print_json(safe_canary_dict(result))
            return 0 if result.status is ObservationStatus.HEALTHY else 3
        if args.command in {"canary-rollback-preview", "canary-rollback-apply"}:
            if args.command == "canary-rollback-apply" and not args.apply:
                raise InstallationValidationError("rollback apply requires explicit --apply")
            result = rollback_canary_package(
                args.root,
                apply=args.command == "canary-rollback-apply",
                live_reviewed=args.live_reviewed,
            )
            print(
                "ROLLBACK APPLY — MANIFEST-OWNED CANARY FILES REMOVED"
                if args.command == "canary-rollback-apply"
                else "ROLLBACK PREVIEW ONLY — NOTHING REMOVED"
            )
            _print_json(safe_canary_dict(result))
            return 0
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
    except UnsafeSandboxError as error:
        print(f"Unsafe sandbox root: {sanitize_message(str(error))}", file=sys.stderr)
        return 6
    except InstallationConflictError as error:
        print(f"Installation conflict: {sanitize_message(str(error))}", file=sys.stderr)
        return 7
    except InstallationValidationError as error:
        print(f"Installation input error: {sanitize_message(str(error))}", file=sys.stderr)
        return 5 if "checksum" in str(error).lower() else 1
    except PilotPolicyDeniedError as error:
        print(f"Pilot target or adapter denied: {sanitize_message(str(error))}", file=sys.stderr)
        return 2
    except UnsafePilotError as error:
        print(f"Production or live pilot request denied: {sanitize_message(str(error))}", file=sys.stderr)
        return 8
    except PilotValidationError as error:
        print(f"Pilot input error: {sanitize_message(str(error))}", file=sys.stderr)
        return 1
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
