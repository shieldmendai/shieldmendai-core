from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
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
    UnsafeSandboxError,
)
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


PLAN_PATH = ROOT / "examples" / "installation" / "plan.yaml"


def plan_data() -> dict:
    return yaml.safe_load(PLAN_PATH.read_text(encoding="utf-8"))


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


if __name__ == "__main__":
    unittest.main()
