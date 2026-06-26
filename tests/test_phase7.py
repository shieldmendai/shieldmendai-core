from __future__ import annotations

import json
import contextlib
import io
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shieldmendai.errors import (
    InstallationConflictError,
    InstallationValidationError,
    PilotPolicyDeniedError,
    PilotValidationError,
    UnsafeSandboxError,
    UnsafePilotError,
)
from shieldmendai.cli import run
from shieldmendai.incidents import IncidentStatus, LocalIncidentStore
from shieldmendai.installation import (
    MANIFEST_NAME,
    inspect_installation,
    load_installation_manifest,
    parse_installation_manifest,
    parse_installation_plan,
    plan_uninstall,
    render_systemd_units,
    simulate_install,
    simulate_uninstall,
    validate_sandbox_root,
)
from shieldmendai.linux_pilot import (
    DisabledProductionLinuxObserver,
    LinuxPilotController,
    observer_capability_catalog,
    parse_pilot_configuration,
    parse_pilot_policy,
    parse_pilot_scenario,
)
from shieldmendai.models import AdapterType, ObservationStatus


PLAN_PATH = ROOT / "examples" / "installation" / "plan.yaml"
PILOT_CONFIG_PATH = ROOT / "examples" / "pilot" / "config.yaml"
PILOT_POLICY_PATH = ROOT / "examples" / "pilot" / "policy.yaml"
PILOT_HEALTHY_PATH = ROOT / "examples" / "pilot" / "scenario-healthy.yaml"
PILOT_UNHEALTHY_PATH = ROOT / "examples" / "pilot" / "scenario-unhealthy.yaml"


def plan_data() -> dict:
    return yaml.safe_load(PLAN_PATH.read_text(encoding="utf-8"))


def pilot_config_data() -> dict:
    return yaml.safe_load(PILOT_CONFIG_PATH.read_text(encoding="utf-8"))


def pilot_policy_data() -> dict:
    return yaml.safe_load(PILOT_POLICY_PATH.read_text(encoding="utf-8"))


def pilot_scenario_data(*, healthy: bool = True) -> dict:
    path = PILOT_HEALTHY_PATH if healthy else PILOT_UNHEALTHY_PATH
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def run_cli(*args: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = run(list(args))
    return code, stdout.getvalue(), stderr.getvalue()


class InstallationModelTests(unittest.TestCase):
    def test_valid_installation_plan_loads(self) -> None:
        plan = parse_installation_plan(plan_data())
        self.assertEqual(plan.installation_id, "shieldmendai-sandbox-example")
        self.assertTrue(plan.simulation)
        self.assertTrue(plan.uninstall_preview_default)

    def test_unknown_schema_and_missing_installation_id_are_rejected(self) -> None:
        unknown = plan_data()
        unknown["schema_version"] = "99.0"
        with self.assertRaises(InstallationValidationError):
            parse_installation_plan(unknown)
        missing = plan_data()
        del missing["installation_id"]
        with self.assertRaises(InstallationValidationError):
            parse_installation_plan(missing)

    def test_service_user_is_noninteractive_without_root_or_sudo(self) -> None:
        user = parse_installation_plan(plan_data()).service_user
        self.assertEqual(user.user, "shieldmendai")
        self.assertFalse(user.interactive_shell)
        self.assertFalse(user.run_as_root)
        self.assertFalse(user.sudo_allowed)
        self.assertIsNone(user.home_directory)
        self.assertTrue(user.additional_scope_requires_review)

    def test_permission_and_ownership_plans_are_safe_and_modeled_only(self) -> None:
        plan = parse_installation_plan(plan_data())
        self.assertTrue(all(item.modeled_only for item in plan.permission_plan))
        self.assertTrue(all(item.modeled_only for item in plan.ownership_plan))
        self.assertFalse(any(item.mode.endswith(("2", "3", "6", "7")) for item in plan.permission_plan))
        self.assertTrue(all(item.owner == "shieldmendai" for item in plan.ownership_plan))

    def test_systemd_templates_are_least_privilege_and_secret_free(self) -> None:
        units = render_systemd_units()
        self.assertEqual(
            set(units),
            {
                "shieldmendai-observer.service",
                "shieldmendai-observer.timer",
                "shieldmendai-incident-maintenance.service",
                "shieldmendai-incident-maintenance.timer",
            },
        )
        serialized = "\n".join(units.values())
        self.assertIn("User=shieldmendai", serialized)
        self.assertIn("NoNewPrivileges=true", serialized)
        self.assertIn("CapabilityBoundingSet=", serialized)
        self.assertNotIn("User=root", serialized)
        self.assertNotIn("password", serialized.lower())
        self.assertNotIn("token", serialized.lower())
        self.assertNotIn("restart", serialized.lower())
        self.assertNotIn("notify", serialized.lower())


class SandboxRootTests(unittest.TestCase):
    def test_temporary_root_is_accepted_and_temp_root_itself_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(validate_sandbox_root(directory), Path(directory))
        with self.assertRaises(UnsafeSandboxError):
            validate_sandbox_root(tempfile.gettempdir())

    def test_production_repository_private_and_traversal_roots_are_rejected(self) -> None:
        for value in (
            "/",
            "/etc",
            "/usr",
            "/var",
            "/opt",
            "/home",
            "/root",
            str(ROOT),
            "/tmp/example/../escape",
            "/root/" + "newbasebot",
        ):
            with self.subTest(value=value), self.assertRaises(UnsafeSandboxError):
                validate_sandbox_root(value)

    def test_symlink_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            target.mkdir()
            link = base / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(UnsafeSandboxError):
                validate_sandbox_root(link)


class SandboxInstallationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.plan = parse_installation_plan(plan_data())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_installation_writes_only_inside_root_and_creates_valid_manifest(self) -> None:
        outside = self.root.parent / f"{self.root.name}-outside"
        result = simulate_install(self.plan, self.root)
        self.assertTrue(result.validation.valid)
        self.assertFalse(result.production_installation_performed)
        self.assertTrue(all(Path(item).is_relative_to(self.root) for item in result.created_files))
        self.assertFalse(outside.exists())
        manifest = load_installation_manifest(self.root)
        self.assertEqual(manifest.installation_id, self.plan.installation_id)
        self.assertTrue(manifest.manifest_checksum)
        self.assertTrue(all(Path(item.sandbox_path).is_relative_to(self.root) for item in manifest.files))

    def test_bootstrap_configuration_has_safe_defaults_and_no_secrets(self) -> None:
        simulate_install(self.plan, self.root)
        data = yaml.safe_load(
            (self.root / "etc" / "shieldmendai" / "pilot.yaml").read_text(encoding="utf-8")
        )
        self.assertTrue(data["local_only"])
        self.assertTrue(data["read_only"])
        self.assertFalse(data["repairs_enabled"])
        self.assertFalse(data["notification_delivery_enabled"])
        self.assertFalse(data["network_access_enabled"])
        self.assertFalse(data["automatic_target_discovery"])
        self.assertEqual(data["secret_references"], [])
        self.assertNotIn("credential", json.dumps(data).lower())

    def test_repeated_installation_is_idempotent(self) -> None:
        first = simulate_install(self.plan, self.root)
        second = simulate_install(self.plan, self.root)
        self.assertFalse(first.idempotent)
        self.assertTrue(second.idempotent)
        self.assertEqual(second.created_files, ())
        self.assertGreater(len(second.unchanged_files), 0)

    def test_installation_conflict_is_detected_and_unrelated_file_is_unchanged(self) -> None:
        unrelated = self.root / "unrelated.txt"
        unrelated.write_text("preserve", encoding="utf-8")
        simulate_install(self.plan, self.root)
        installed = self.root / "etc" / "shieldmendai" / "pilot.yaml"
        installed.write_text("modified", encoding="utf-8")
        with self.assertRaises(InstallationConflictError):
            simulate_install(self.plan, self.root)
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "preserve")

    def test_manifest_checksum_failure_is_detected(self) -> None:
        simulate_install(self.plan, self.root)
        path = self.root / "var" / "lib" / "shieldmendai" / MANIFEST_NAME
        data = json.loads(path.read_text(encoding="utf-8"))
        data["package_version"] = "tampered"
        with self.assertRaisesRegex(InstallationValidationError, "checksum"):
            parse_installation_manifest(data)

    def test_mapped_path_symlink_escape_is_rejected(self) -> None:
        outside = self.root.parent / f"{self.root.name}-escape"
        outside.mkdir(exist_ok=True)
        (self.root / "etc").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(UnsafeSandboxError):
            simulate_install(self.plan, self.root)

    def test_no_host_mutation_commands_or_permission_changes_occur(self) -> None:
        with (
            mock.patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
            mock.patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
            mock.patch.object(os, "system", side_effect=AssertionError("system")),
            mock.patch.object(os, "chmod", side_effect=AssertionError("chmod")),
            mock.patch.object(os, "chown", side_effect=AssertionError("chown")),
            mock.patch.object(socket, "create_connection", side_effect=AssertionError("socket")),
        ):
            simulate_install(self.plan, self.root)

    def test_inspection_detects_modified_installed_file(self) -> None:
        simulate_install(self.plan, self.root)
        path = self.root / "opt" / "shieldmendai" / "bin" / "shieldmendai"
        path.write_text("changed", encoding="utf-8")
        result = inspect_installation(self.root)
        self.assertFalse(result.valid)
        self.assertIn("/opt/shieldmendai/bin/shieldmendai", result.conflicts)


class SandboxUninstallationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.plan = parse_installation_plan(plan_data())
        simulate_install(self.plan, self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_preview_modifies_nothing(self) -> None:
        before = {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }
        result = simulate_uninstall(self.root)
        after = {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }
        self.assertTrue(result.preview_only)
        self.assertEqual(before, after)
        self.assertEqual(result.removed_files, ())

    def test_fixture_removal_requires_explicit_flag(self) -> None:
        with self.assertRaises(InstallationValidationError):
            simulate_uninstall(self.root, preview_only=False)

    def test_fixture_uninstall_removes_only_recorded_files_and_preserves_unknown(self) -> None:
        unrelated = self.root / "unrelated.txt"
        unrelated.write_text("preserve", encoding="utf-8")
        plan = plan_uninstall(self.root)
        self.assertIn(str(unrelated), plan.unknown_files)
        result = simulate_uninstall(
            self.root,
            preview_only=False,
            remove_generated_fixtures=True,
        )
        self.assertTrue(result.removed_files)
        self.assertTrue(unrelated.exists())
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "preserve")
        self.assertFalse(result.production_installation_removed)

    def test_modified_installed_file_blocks_removal(self) -> None:
        path = self.root / "etc" / "shieldmendai" / "pilot.yaml"
        path.write_text("modified", encoding="utf-8")
        preview = plan_uninstall(self.root)
        self.assertIn(str(path), preview.conflicts)
        with self.assertRaises(InstallationConflictError):
            simulate_uninstall(
                self.root,
                preview_only=False,
                remove_generated_fixtures=True,
            )
        self.assertTrue(path.exists())


class PilotPolicyAndAllowlistTests(unittest.TestCase):
    def test_safe_policy_defaults_and_unknown_fields(self) -> None:
        policy = parse_pilot_policy(pilot_policy_data())
        self.assertTrue(policy.local_only)
        self.assertTrue(policy.read_only)
        self.assertTrue(policy.sandbox_only)
        self.assertFalse(policy.repairs_enabled)
        self.assertFalse(policy.notifications_enabled)
        self.assertFalse(policy.network_enabled)
        self.assertFalse(policy.process_enumeration_enabled)
        self.assertFalse(policy.systemd_enabled)
        self.assertTrue(policy.review_required)
        unknown = pilot_policy_data()
        unknown["unexpected"] = True
        with self.assertRaises(PilotValidationError):
            parse_pilot_policy(unknown)

    def test_wildcard_duplicate_and_unknown_adapter_are_rejected(self) -> None:
        wildcard = pilot_config_data()
        wildcard["targets"][0]["target_id"] = "*"
        with self.assertRaises(PilotValidationError):
            parse_pilot_configuration(wildcard)
        duplicate = pilot_config_data()
        duplicate["targets"].append(dict(duplicate["targets"][0]))
        with self.assertRaises(PilotValidationError):
            parse_pilot_configuration(duplicate)
        unknown = pilot_config_data()
        unknown["targets"][0]["adapter_type"] = "unknown_adapter"
        with self.assertRaises(PilotValidationError):
            parse_pilot_configuration(unknown)

    def test_nonlocal_and_mutation_enabled_targets_are_denied(self) -> None:
        nonlocal_target = pilot_config_data()
        nonlocal_target["targets"][0]["local_only"] = False
        with self.assertRaises(PilotPolicyDeniedError):
            parse_pilot_configuration(nonlocal_target)
        mutable = pilot_config_data()
        mutable["targets"][0]["mutation_enabled"] = True
        with self.assertRaises(PilotPolicyDeniedError):
            parse_pilot_configuration(mutable)

    def test_production_live_and_capability_enabling_policies_are_denied(self) -> None:
        for key in (
            "repairs_enabled",
            "notifications_enabled",
            "network_enabled",
            "process_enumeration_enabled",
            "systemd_enabled",
        ):
            data = pilot_policy_data()
            data[key] = True
            with self.subTest(key=key), self.assertRaises(UnsafePilotError):
                parse_pilot_policy(data)
        data = pilot_policy_data()
        data["sandbox_only"] = False
        with self.assertRaises(UnsafePilotError):
            parse_pilot_policy(data)

    def test_linux_observer_capabilities_are_read_only_and_production_disabled(self) -> None:
        capabilities = observer_capability_catalog()
        self.assertGreaterEqual(len(capabilities), 10)
        for item in capabilities:
            self.assertTrue(item.read_only)
            self.assertTrue(item.fixture_simulation_available)
            self.assertFalse(item.production_adapter_available)
            self.assertFalse(item.mutation_available)

    def test_production_adapter_always_denies(self) -> None:
        adapter = DisabledProductionLinuxObserver(AdapterType.SYSTEMD_SERVICE)
        with self.assertRaises(UnsafePilotError):
            adapter.observe()


class PilotControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "fixtures").mkdir()
        (self.root / "fixtures" / "status.json").write_text('{"status":"ok"}\n', encoding="utf-8")
        (self.root / "fixtures" / "tool").write_text("fixture", encoding="utf-8")
        self.config = parse_pilot_configuration(pilot_config_data())
        self.policy = parse_pilot_policy(pilot_policy_data())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_healthy_service_process_file_and_executable_normalize(self) -> None:
        result = LinuxPilotController().run_cycle(
            self.config,
            self.policy,
            parse_pilot_scenario(pilot_scenario_data()),
            self.root,
        )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.cycle_count, 1)
        self.assertEqual(len(result.findings), 4)
        self.assertTrue(all(item.status is ObservationStatus.HEALTHY for item in result.findings))
        self.assertIn("fixture-disabled", result.skipped_target_ids)
        self.assertFalse(result.production_system_observed)

    def test_unhealthy_findings_create_sanitized_integrity_checked_incidents(self) -> None:
        (self.root / "fixtures" / "status.json").write_text("{invalid", encoding="utf-8")
        (self.root / "fixtures" / "tool").unlink()
        result = LinuxPilotController().run_cycle(
            self.config,
            self.policy,
            parse_pilot_scenario(pilot_scenario_data(healthy=False)),
            self.root,
        )
        self.assertEqual(result.exit_code, 3)
        self.assertEqual(len(result.incident_references), 4)
        store = LocalIncidentStore(self.root / "var" / "lib" / "shieldmendai" / "incidents")
        records = store.list_records()
        self.assertEqual(len(records), 8)
        latest = {
            incident_id: max(
                (item for item in records if item.incident_id == incident_id),
                key=lambda item: item.metadata.record_version,
            )
            for incident_id in result.incident_references
        }
        self.assertTrue(all(item.status is IncidentStatus.OPEN for item in latest.values()))
        self.assertTrue(all(item.metadata.checksum for item in records))
        serialized = json.dumps([item.to_safe_dict() for item in records])
        self.assertNotIn("password", serialized.lower())
        self.assertNotIn("token", serialized.lower())

    def test_healthy_recheck_resolves_existing_incident(self) -> None:
        unhealthy = pilot_scenario_data(healthy=False)
        unhealthy["observations"] = [unhealthy["observations"][0]]
        policy = pilot_policy_data()
        policy["allowed_target_ids"] = ["fixture-service"]
        policy["maximum_targets"] = 1
        LinuxPilotController().run_cycle(
            self.config,
            parse_pilot_policy(policy),
            parse_pilot_scenario(unhealthy),
            self.root,
        )
        healthy = pilot_scenario_data()
        healthy["scenario_id"] = "healthy-recheck"
        healthy["observed_at"] = "2030-01-01T00:10:00Z"
        healthy["observations"] = [healthy["observations"][0]]
        result = LinuxPilotController().run_cycle(
            self.config,
            parse_pilot_policy(policy),
            parse_pilot_scenario(healthy),
            self.root,
        )
        self.assertEqual(result.exit_code, 0)
        records = LocalIncidentStore(
            self.root / "var" / "lib" / "shieldmendai" / "incidents"
        ).list_records()
        latest = max(records, key=lambda item: item.metadata.record_version)
        self.assertEqual(latest.status, IncidentStatus.RESOLVED)

    def test_unknown_target_and_disallowed_adapter_are_denied(self) -> None:
        unknown = pilot_scenario_data()
        unknown["observations"][0]["target_id"] = "unknown-target"
        with self.assertRaises(PilotPolicyDeniedError):
            LinuxPilotController().run_cycle(
                self.config, self.policy, parse_pilot_scenario(unknown), self.root
            )
        policy = pilot_policy_data()
        policy["allowed_adapter_types"].remove("systemd_service")
        with self.assertRaises(PilotPolicyDeniedError):
            LinuxPilotController().run_cycle(
                self.config,
                parse_pilot_policy(policy),
                parse_pilot_scenario(pilot_scenario_data()),
                self.root,
            )

    def test_exact_fixture_path_allowlist_and_symlink_escape_are_enforced(self) -> None:
        scenario = pilot_scenario_data()
        scenario["observations"] = [scenario["observations"][2]]
        policy = pilot_policy_data()
        policy["allowed_target_ids"] = ["fixture-json"]
        policy["maximum_targets"] = 1
        scenario["observations"][0]["fixture_path"] = "fixtures/other.json"
        with self.assertRaises(PilotPolicyDeniedError):
            LinuxPilotController().run_cycle(
                self.config,
                parse_pilot_policy(policy),
                parse_pilot_scenario(scenario),
                self.root,
            )
        outside = self.root.parent / f"{self.root.name}-pilot-escape.json"
        outside.write_text("{}", encoding="utf-8")
        (self.root / "fixtures" / "status.json").unlink()
        (self.root / "fixtures" / "status.json").symlink_to(outside)
        scenario["observations"][0]["fixture_path"] = "fixtures/status.json"
        with self.assertRaises(Exception):
            LinuxPilotController().run_cycle(
                self.config,
                parse_pilot_policy(policy),
                parse_pilot_scenario(scenario),
                self.root,
            )

    def test_production_repair_notification_and_network_requests_are_denied(self) -> None:
        for key in (
            "requested_production_observation",
            "requested_repair",
            "requested_notification",
        ):
            data = pilot_scenario_data()
            data[key] = True
            with self.subTest(key=key), self.assertRaises(UnsafePilotError):
                LinuxPilotController().run_cycle(
                    self.config, self.policy, parse_pilot_scenario(data), self.root
                )
        network_config = pilot_config_data()
        network_config["targets"][0]["adapter_type"] = "http"
        network_config["targets"][0]["observation_type"] = "http_health"
        network_config["targets"][0]["incident_category"] = "http_unhealthy"
        network_policy = pilot_policy_data()
        network_policy["allowed_target_ids"] = ["fixture-service"]
        network_policy["allowed_adapter_types"] = ["http"]
        network_policy["prohibited_adapter_types"] = []
        network_policy["maximum_targets"] = 1
        scenario = pilot_scenario_data()
        scenario["observations"] = [scenario["observations"][0]]
        with self.assertRaises(PilotPolicyDeniedError):
            LinuxPilotController().run_cycle(
                parse_pilot_configuration(network_config),
                parse_pilot_policy(network_policy),
                parse_pilot_scenario(scenario),
                self.root,
            )

    def test_cycle_uses_no_live_system_network_process_subprocess_or_sleep(self) -> None:
        with (
            mock.patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
            mock.patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
            mock.patch.object(os, "system", side_effect=AssertionError("system")),
            mock.patch.object(socket, "create_connection", side_effect=AssertionError("socket")),
            mock.patch.object(socket.socket, "connect", side_effect=AssertionError("socket")),
            mock.patch.object(time, "sleep", side_effect=AssertionError("sleep")),
            mock.patch.dict(os.environ, {}, clear=True),
        ):
            result = LinuxPilotController().run_cycle(
                self.config,
                self.policy,
                parse_pilot_scenario(pilot_scenario_data()),
                self.root,
            )
        self.assertEqual(result.cycle_count, 1)
        self.assertFalse(result.network_used)
        self.assertFalse(result.repair_executed)
        self.assertFalse(result.notification_sent)
        self.assertTrue(all(not item.systemd_contacted for item in result.audit_events))
        self.assertTrue(all(not item.process_enumerated for item in result.audit_events))

    def test_cycle_is_deterministic(self) -> None:
        first_root = self.root
        first = LinuxPilotController().run_cycle(
            self.config,
            self.policy,
            parse_pilot_scenario(pilot_scenario_data()),
            first_root,
        )
        with tempfile.TemporaryDirectory() as directory:
            second_root = Path(directory)
            (second_root / "fixtures").mkdir()
            (second_root / "fixtures" / "status.json").write_text(
                '{"status":"ok"}\n', encoding="utf-8"
            )
            (second_root / "fixtures" / "tool").write_text("fixture", encoding="utf-8")
            second = LinuxPilotController().run_cycle(
                self.config,
                self.policy,
                parse_pilot_scenario(pilot_scenario_data()),
                second_root,
            )
        self.assertEqual(
            [item.to_safe_dict() for item in first.findings],
            [item.to_safe_dict() for item in second.findings],
        )
        self.assertEqual(first.audit_events, second.audit_events)


class Phase7CliTests(unittest.TestCase):
    def test_installation_cli_labels_and_exit_codes(self) -> None:
        code, output, error = run_cli("inspect-installation-plan", str(PLAN_PATH))
        self.assertEqual(code, 0)
        self.assertIn("INSTALLATION PLAN ONLY", output)
        self.assertEqual(error, "")
        self.assertIn(
            "SYSTEMD TEMPLATE PREVIEW ONLY",
            run_cli("render-systemd-units", str(PLAN_PATH))[1],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, output, _ = run_cli("simulate-install", str(PLAN_PATH), str(root))
            self.assertEqual(code, 0)
            self.assertIn("SANDBOX INSTALLATION ONLY", output)
            self.assertIn(
                "SANDBOX INSTALLATION INSPECTION ONLY",
                run_cli("inspect-installation", str(root))[1],
            )
            before = sorted(str(item) for item in root.rglob("*"))
            code, output, _ = run_cli("preview-uninstall", str(root))
            self.assertEqual(code, 0)
            self.assertIn("UNINSTALL PREVIEW ONLY", output)
            self.assertEqual(before, sorted(str(item) for item in root.rglob("*")))
            self.assertEqual(run_cli("simulate-uninstall", str(root))[0], 1)
            code, output, _ = run_cli(
                "simulate-uninstall", str(root), "--remove-generated-fixtures"
            )
            self.assertEqual(code, 0)
            self.assertIn("NO PRODUCTION FILES AFFECTED", output)
        self.assertEqual(run_cli("simulate-install", str(PLAN_PATH), "/etc")[0], 6)

    def test_pilot_cli_labels_and_exit_codes(self) -> None:
        self.assertIn(
            "NO LIVE SYSTEM OBSERVED",
            run_cli("inspect-pilot-policy", str(PILOT_POLICY_PATH))[1],
        )
        self.assertIn(
            "PRODUCTION ADAPTERS DISABLED",
            run_cli("list-linux-observers")[1],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixtures").mkdir()
            (root / "fixtures" / "status.json").write_text('{"ok":true}', encoding="utf-8")
            (root / "fixtures" / "tool").write_text("fixture", encoding="utf-8")
            code, output, _ = run_cli(
                "simulate-linux-pilot",
                str(PILOT_CONFIG_PATH),
                str(PILOT_POLICY_PATH),
                str(PILOT_HEALTHY_PATH),
                str(root),
            )
            self.assertEqual(code, 0)
            self.assertIn("READ-ONLY PILOT SIMULATION", output)
            (root / "fixtures" / "status.json").write_text("{invalid", encoding="utf-8")
            (root / "fixtures" / "tool").unlink()
            self.assertEqual(
                run_cli(
                    "simulate-linux-pilot",
                    str(PILOT_CONFIG_PATH),
                    str(PILOT_POLICY_PATH),
                    str(PILOT_UNHEALTHY_PATH),
                    str(root),
                )[0],
                3,
            )

    def test_denied_target_and_production_request_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixtures").mkdir()
            scenario = pilot_scenario_data()
            scenario["observations"][0]["target_id"] = "unknown-target"
            scenario_path = root / "unknown.yaml"
            scenario_path.write_text(yaml.safe_dump(scenario), encoding="utf-8")
            self.assertEqual(
                run_cli(
                    "simulate-linux-pilot",
                    str(PILOT_CONFIG_PATH),
                    str(PILOT_POLICY_PATH),
                    str(scenario_path),
                    str(root),
                )[0],
                2,
            )
            scenario = pilot_scenario_data()
            scenario["requested_production_observation"] = True
            scenario_path.write_text(yaml.safe_dump(scenario), encoding="utf-8")
            self.assertEqual(
                run_cli(
                    "simulate-linux-pilot",
                    str(PILOT_CONFIG_PATH),
                    str(PILOT_POLICY_PATH),
                    str(scenario_path),
                    str(root),
                )[0],
                8,
            )


if __name__ == "__main__":
    unittest.main()
