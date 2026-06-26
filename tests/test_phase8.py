from __future__ import annotations

import contextlib
import io
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shieldmendai.cli import run
from shieldmendai.dedicated_canary import (
    CANARY_IDENTITY,
    DEMO_TARGET_ID,
    FORBIDDEN_PRIVATE_PATH,
    default_canary_config,
    install_canary_package,
    load_canary_manifest,
    observe_demo_health,
    parse_canary_config,
    render_canary_systemd_units,
    rollback_canary_package,
    validate_canary_root,
    validate_host_identity,
)
from shieldmendai.errors import InstallationConflictError, InstallationValidationError, PilotPolicyDeniedError
from shieldmendai.incidents import IncidentStatus, LocalIncidentStore
from shieldmendai.models import ObservationStatus


CONFIG_PATH = ROOT / "examples" / "canary" / "dedicated-canary.yaml"


def config_data() -> dict:
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))


def run_cli(*args: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = run(list(args))
    return code, stdout.getvalue(), stderr.getvalue()


class CanaryConfigurationTests(unittest.TestCase):
    def test_valid_dedicated_canary_configuration(self) -> None:
        config = parse_canary_config(config_data())
        self.assertEqual(config.canary_identity, CANARY_IDENTITY)
        self.assertEqual(config.targets[0].target_id, DEMO_TARGET_ID)

    def test_unknown_fields_rejected(self) -> None:
        data = config_data()
        data["extra"] = True
        with self.assertRaises(InstallationValidationError):
            parse_canary_config(data)

    def test_repairs_notifications_network_and_process_discovery_remain_disabled(self) -> None:
        for key in (
            "repairs_enabled",
            "notification_delivery_enabled",
            "network_access_enabled",
            "process_enumeration_enabled",
            "automatic_target_discovery",
        ):
            data = config_data()
            data[key] = True
            with self.subTest(key=key), self.assertRaises(InstallationValidationError):
                parse_canary_config(data)

    def test_unknown_wildcard_nonlocal_and_mutation_targets_denied(self) -> None:
        data = config_data()
        data["targets"][0]["target_id"] = "other-target"
        with self.assertRaises(PilotPolicyDeniedError):
            parse_canary_config(data)
        data = config_data()
        data["targets"][0]["target_id"] = "*"
        with self.assertRaises(InstallationValidationError):
            parse_canary_config(data)
        data = config_data()
        data["targets"][0]["local_only"] = False
        with self.assertRaises(PilotPolicyDeniedError):
            parse_canary_config(data)
        data = config_data()
        data["targets"][0]["mutation_enabled"] = True
        with self.assertRaises(PilotPolicyDeniedError):
            parse_canary_config(data)

    def test_exact_demo_target_accepted(self) -> None:
        self.assertEqual(default_canary_config().targets[0].target_id, DEMO_TARGET_ID)


class CanaryHostAndPathTests(unittest.TestCase):
    def test_host_identity_mismatch_rejected_and_explicit_identity_accepted(self) -> None:
        config = default_canary_config()
        self.assertFalse(validate_host_identity(config, actual_hostname="wrong").accepted)
        self.assertTrue(
            validate_host_identity(
                config, actual_hostname="wrong", canary_identity=CANARY_IDENTITY
            ).accepted
        )

    def test_repository_private_traversal_and_symlink_roots_rejected(self) -> None:
        with self.assertRaises(InstallationValidationError):
            validate_canary_root(ROOT)
        with self.assertRaises(InstallationValidationError):
            validate_canary_root(FORBIDDEN_PRIVATE_PATH)
        with self.assertRaises(InstallationValidationError):
            validate_canary_root("/tmp/example/../escape")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            target.mkdir()
            link = base / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(InstallationValidationError):
                validate_canary_root(link)

    def test_public_ip_and_source_host_rejected(self) -> None:
        config = default_canary_config()
        with self.assertRaises(InstallationValidationError):
            validate_host_identity(config, actual_hostname="198" + ".51.100.10")


class CanaryInstallationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = default_canary_config()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_preview_changes_nothing_and_apply_requires_flag(self) -> None:
        before = tuple(self.root.rglob("*"))
        result = install_canary_package(self.config, self.root, actual_hostname="shieldmendai")
        self.assertTrue(result.preview_only)
        self.assertFalse(result.changed)
        self.assertEqual(before, tuple(self.root.rglob("*")))
        code, _, stderr = run_cli(
            "canary-install-apply",
            str(self.root),
            "--actual-hostname",
            "shieldmendai",
        )
        self.assertNotEqual(code, 0)
        self.assertIn("requires explicit", stderr)

    def test_manifest_is_checksummed_install_idempotent_and_conflicts_block_overwrite(self) -> None:
        first = install_canary_package(
            self.config, self.root, apply=True, actual_hostname="shieldmendai"
        )
        manifest = load_canary_manifest(self.root)
        self.assertRegex(manifest.manifest_checksum, r"^[0-9a-f]{64}$")
        second = install_canary_package(
            self.config, self.root, apply=True, actual_hostname="shieldmendai"
        )
        self.assertFalse(second.changed)
        self.assertGreater(len(second.preserved_files), 0)
        conflict = self.root / "etc/shieldmendai/dedicated-canary.yaml"
        conflict.write_text("changed\n", encoding="utf-8")
        with self.assertRaises(InstallationConflictError):
            install_canary_package(
                self.config, self.root, apply=True, actual_hostname="shieldmendai"
            )

    def test_unrelated_files_and_root_demo_file_are_preserved(self) -> None:
        unrelated = self.root / "unknown.txt"
        unrelated.write_text("keep\n", encoding="utf-8")
        result = install_canary_package(
            self.config, self.root, apply=True, actual_hostname="shieldmendai"
        )
        self.assertTrue(unrelated.exists())
        self.assertIn("/root/shieldmend_demo.sh", json.dumps(result.audit_record))

    def test_service_user_runtime_and_systemd_units_are_least_privilege(self) -> None:
        units = render_canary_systemd_units()
        serialized = "\n".join(units.values())
        self.assertEqual(
            set(units),
            {
                "shieldmendai-observer.service",
                "shieldmendai-observer.timer",
                "shieldmendai-incident-maintenance.service",
                "shieldmendai-incident-maintenance.timer",
                "shieldmendai-demo.service",
            },
        )
        for required in (
            "User=shieldmendai",
            "Group=shieldmendai",
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "UMask=0077",
            "PrivateNetwork=true",
            "IPAddressDeny=any",
            "ReadOnlyPaths=",
            "ReadWritePaths=",
        ):
            self.assertIn(required, serialized)
        self.assertNotIn("User=root", serialized)
        self.assertNotIn("sudo", serialized.lower())
        self.assertNotIn("telegram", serialized.lower())
        self.assertNotIn("curl", serialized.lower())
        self.assertNotIn("repair", serialized.lower().replace("repair=disabled", ""))

    def test_cli_labels(self) -> None:
        code, stdout, _ = run_cli("render-canary-systemd-units")
        self.assertEqual(code, 0)
        self.assertIn("PREVIEW ONLY", stdout)
        code, stdout, _ = run_cli("inspect-canary-config", str(CONFIG_PATH))
        self.assertEqual(code, 0)
        self.assertIn("VERIFICATION ONLY", stdout)


class CanaryObservationAndRollbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = default_canary_config()
        install_canary_package(self.config, self.root, apply=True, actual_hostname="shieldmendai")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_healthy_stopped_and_manual_recovery_workflow(self) -> None:
        healthy = observe_demo_health(
            self.config, self.root, observed_at="2026-06-26T00:00:00Z"
        )
        self.assertEqual(healthy.status, ObservationStatus.HEALTHY)
        health = self.root / "var/lib/shieldmendai/demo/health.json"
        before = health.read_bytes()
        health.unlink()
        unhealthy = observe_demo_health(
            self.config, self.root, observed_at="2026-06-26T00:05:00Z"
        )
        self.assertEqual(unhealthy.status, ObservationStatus.UNHEALTHY)
        self.assertFalse(unhealthy.repair_executed)
        self.assertFalse(unhealthy.notification_sent)
        self.assertFalse(unhealthy.network_used)
        self.assertFalse(health.exists())
        health.write_bytes(before)
        recovered = observe_demo_health(
            self.config, self.root, observed_at="2026-06-26T00:10:00Z"
        )
        self.assertEqual(recovered.status, ObservationStatus.HEALTHY)
        store = LocalIncidentStore(self.root / "var/lib/shieldmendai/incidents")
        latest = max(store.list_records(), key=lambda item: item.metadata.record_version)
        self.assertEqual(latest.status, IncidentStatus.RESOLVED)

    def test_observer_uses_one_cycle_and_no_mutating_boundaries(self) -> None:
        with mock.patch("os.system", side_effect=AssertionError("os.system forbidden")), mock.patch(
            "socket.socket", side_effect=AssertionError("socket forbidden")
        ):
            result = observe_demo_health(
                self.config, self.root, observed_at="2026-06-26T00:00:00Z"
            )
        self.assertEqual(result.cycle_count, 1)
        self.assertFalse(result.process_mutation_used)

    def test_rollback_preview_apply_unknown_preserved_and_modified_blocks(self) -> None:
        unknown = self.root / "var/lib/shieldmendai/unknown.txt"
        unknown.write_text("keep\n", encoding="utf-8")
        preview = rollback_canary_package(self.root)
        self.assertTrue(preview.preview_only)
        self.assertTrue((self.root / "etc/shieldmendai/dedicated-canary.yaml").exists())
        self.assertTrue(unknown.exists())
        modified = self.root / "etc/shieldmendai/dedicated-canary.yaml"
        original = modified.read_text(encoding="utf-8")
        modified.write_text(original + "# changed\n", encoding="utf-8")
        with self.assertRaises(InstallationConflictError):
            rollback_canary_package(self.root, apply=True)
        modified.write_text(original, encoding="utf-8")
        applied = rollback_canary_package(self.root, apply=True)
        self.assertFalse((self.root / "etc/shieldmendai/dedicated-canary.yaml").exists())
        self.assertTrue(unknown.exists())
        self.assertGreater(len(applied.removed_files), 0)

    def test_audits_are_sanitized(self) -> None:
        result = install_canary_package(
            self.config, self.root, apply=True, actual_hostname="shieldmendai"
        )
        serialized = json.dumps(result.audit_record).lower()
        self.assertNotIn("restricted_material", serialized)
        self.assertIn('"materials_copied": false', serialized)
        self.assertNotIn("token", serialized)
        self.assertNotIn("198.51.100", serialized)


class CanaryRepositorySafetyTests(unittest.TestCase):
    def test_no_real_ip_private_server_info_credentials_or_forbidden_access_in_tracked_files(self) -> None:
        forbidden = "/root/" + "newbasebot"
        paths = [
            SRC / "shieldmendai" / "dedicated_canary.py",
            CONFIG_PATH,
            ROOT / "docs" / "PHASE8_CANARY_RUNBOOK.md",
        ]
        for path in paths:
            text = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotRegex(text, r"\b(?:\d{1,3}\.){3}\d{1,3}\b", path)
            if path.name != "PHASE8_CANARY_RUNBOOK.md":
                self.assertNotIn(forbidden, text)
            self.assertNotRegex(text.lower(), r"(api_key|password|bearer\s+|private key)")

    def test_forbidden_source_was_not_accessed_by_phase8_code(self) -> None:
        module_text = (SRC / "shieldmendai" / "dedicated_canary.py").read_text(encoding="utf-8")
        self.assertNotIn('Path("/root/newbasebot")', module_text)
        self.assertNotIn("os.listdir", module_text)
        self.assertNotIn("subprocess", module_text)
        self.assertNotIn("requests", module_text)
        self.assertNotIn("urllib", module_text)


if __name__ == "__main__":
    unittest.main()
