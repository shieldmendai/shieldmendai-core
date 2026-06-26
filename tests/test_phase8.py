from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
import subprocess
import socket
import tempfile
import unittest
import zipfile
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
    RUNTIME_CLI,
    default_canary_config,
    install_canary_package,
    install_offline_runtime,
    load_canary_manifest,
    observe_demo_health,
    parse_canary_config,
    render_canary_systemd_units,
    rollback_canary_package,
    service_user_ownership_plan,
    validate_canary_root,
    validate_host_identity,
    verify_canary_systemd_fixture,
    verify_runtime_wheel,
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

    def test_actual_file_modes_are_enforced_and_recorded(self) -> None:
        install_canary_package(self.config, self.root, apply=True, actual_hostname="shieldmendai")
        launcher = self.root / "opt/shieldmendai/bin/shieldmendai"
        config = self.root / "etc/shieldmendai/dedicated-canary.yaml"
        unit = self.root / "etc/systemd/system/shieldmendai-observer.service"
        audit = self.root / "var/lib/shieldmendai/installation/shieldmendai-canary-installation-audit.json"
        manifest_file = self.root / "var/lib/shieldmendai/installation/shieldmendai-canary-installation-manifest.json"
        self.assertEqual(stat.S_IMODE(launcher.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(unit.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(audit.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(manifest_file.stat().st_mode), 0o640)
        manifest = load_canary_manifest(self.root)
        recorded = {item.path: item.mode for item in manifest.files}
        for path, mode in recorded.items():
            actual = self.root.joinpath(*Path(path).parts[1:])
            self.assertEqual(mode, f"{stat.S_IMODE(actual.stat().st_mode):04o}")
        self.assertEqual(recorded["/opt/shieldmendai/bin/shieldmendai"], "0750")
        self.assertEqual(recorded["/etc/shieldmendai/dedicated-canary.yaml"], "0640")
        self.assertEqual(recorded["/etc/systemd/system/shieldmendai-observer.service"], "0644")

    def test_chmod_remains_confined_to_temporary_root(self) -> None:
        touched: list[Path] = []
        original = Path.chmod

        def audited_chmod(path: Path, mode: int) -> None:
            touched.append(path)
            self.assertTrue(path.resolve(strict=True).is_relative_to(self.root))
            original(path, mode)

        with mock.patch.object(Path, "chmod", audited_chmod):
            install_canary_package(self.config, self.root, apply=True, actual_hostname="shieldmendai")
        self.assertTrue(touched)

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
        self.assertIn(f"ExecStart={RUNTIME_CLI} canary-observe", serialized)
        self.assertIn(f"ExecStart={RUNTIME_CLI} preview-retention", serialized)
        self.assertNotIn("/opt/shieldmendai/bin/shieldmendai canary-observe", serialized)
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

    def test_service_user_and_ownership_plan_is_reviewed_least_privilege(self) -> None:
        plan = service_user_ownership_plan()
        self.assertEqual(plan.user, "shieldmendai")
        self.assertEqual(plan.group, "shieldmendai")
        self.assertEqual(plan.shell, "/usr/sbin/nologin")
        self.assertIsNone(plan.home_directory)
        self.assertTrue(plan.system_account)
        self.assertFalse(plan.sudo_allowed)
        self.assertFalse(plan.run_as_root)
        ownership = {item["path"]: item for item in plan.ownership}
        self.assertEqual(ownership["/etc/shieldmendai"]["owner"], "root")
        self.assertEqual(ownership["/etc/shieldmendai"]["group"], "shieldmendai")
        self.assertEqual(ownership["/var/lib/shieldmendai"]["owner"], "shieldmendai")
        self.assertEqual(ownership["/var/log/shieldmendai"]["group"], "shieldmendai")
        self.assertTrue(all(not item["mode"].endswith(("2", "3", "6", "7")) for item in plan.ownership))

    def test_static_systemd_fixture_verification(self) -> None:
        install_canary_package(self.config, self.root, apply=True, actual_hostname="shieldmendai")
        runtime_cli = self.root / "opt/shieldmendai/venv/bin/shieldmendai"
        runtime_cli.parent.mkdir(parents=True)
        runtime_cli.write_text("#!/usr/bin/env python3\nprint('ok')\n", encoding="utf-8")
        runtime_cli.chmod(0o750)
        result = verify_canary_systemd_fixture(self.root)
        self.assertTrue(result.valid)
        self.assertIn("temporary-root fixture", result.limitation)


class CanaryRuntimeInstallationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.wheel = self.root / "shieldmendai-0.4.0-py3-none-any.whl"
        self._write_wheel(self.wheel, name="shieldmendai", version="0.4.0")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_wheel(self, path: Path, *, name: str, version: str) -> None:
        dist = f"{name.replace('-', '_')}-{version}.dist-info"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(f"{dist}/METADATA", f"Name: {name}\nVersion: {version}\n")
            archive.writestr(f"{dist}/WHEEL", "Wheel-Version: 1.0\n")

    def test_runtime_wheel_validation_rejects_invalid_inputs(self) -> None:
        verification = verify_runtime_wheel(self.wheel)
        self.assertEqual(verification.package_name, "shieldmendai")
        self.assertRegex(verification.sha256, r"^[0-9a-f]{64}$")
        bad_name = self.root / "other-0.4.0-py3-none-any.whl"
        self._write_wheel(bad_name, name="other", version="0.4.0")
        with self.assertRaises(InstallationValidationError):
            verify_runtime_wheel(bad_name)
        bad_version = self.root / "shieldmendai-9.9.9-py3-none-any.whl"
        self._write_wheel(bad_version, name="shieldmendai", version="9.9.9")
        with self.assertRaises(InstallationValidationError):
            verify_runtime_wheel(bad_version)
        with self.assertRaises(InstallationValidationError):
            verify_runtime_wheel(self.wheel, expected_sha256="0" * 64)
        with self.assertRaises(InstallationValidationError):
            verify_runtime_wheel(str(self.root / "../escape.whl"))
        link = self.root / "linked.whl"
        link.symlink_to(self.wheel)
        with self.assertRaises(InstallationValidationError):
            verify_runtime_wheel(link)

    def test_runtime_install_preview_and_apply_use_offline_no_deps_commands(self) -> None:
        runtime = self.root / "runtime"
        preview = install_offline_runtime(self.wheel, runtime)
        self.assertTrue(preview.preview_only)
        self.assertFalse(runtime.exists())
        def create_runtime(command: tuple[str, ...], **_: object) -> None:
            runtime.mkdir(exist_ok=True)
            bin_dir = runtime / "bin"
            bin_dir.mkdir(exist_ok=True)
            python = bin_dir / "python"
            python.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            python.chmod(0o750)
            cli = bin_dir / "shieldmendai"
            cli.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            cli.chmod(0o750)

        with mock.patch("shieldmendai.dedicated_canary._run_process", side_effect=create_runtime) as run_mock:
            result = install_offline_runtime(self.wheel, runtime, apply=True)
        self.assertFalse(result.preview_only)
        calls = [tuple(call.args[0]) for call in run_mock.call_args_list]
        self.assertIn(("python3", "-m", "venv", "--system-site-packages", str(runtime)), calls)
        pip_calls = [call for call in calls if "-m" in call and "pip" in call]
        self.assertEqual(len(pip_calls), 1)
        self.assertIn("--no-deps", pip_calls[0])
        self.assertIn("--no-index", pip_calls[0])
        self.assertNotIn("http", " ".join(pip_calls[0]).lower())
        self.assertTrue((runtime / "shieldmendai-runtime-installation.json").exists())

    def test_runtime_install_rejects_traversal_symlink_and_conflicting_runtime(self) -> None:
        with self.assertRaises(InstallationValidationError):
            install_offline_runtime(self.wheel, str(self.root / "../runtime"))
        target = self.root / "target"
        target.mkdir()
        link = self.root / "runtime-link"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(InstallationValidationError):
            install_offline_runtime(self.wheel, link)
        runtime = self.root / "runtime"
        runtime.mkdir()
        (runtime / "foreign.txt").write_text("not owned\n", encoding="utf-8")
        with self.assertRaises(InstallationConflictError):
            install_offline_runtime(self.wheel, runtime, apply=True)

    def test_runtime_install_idempotent_existing_marker(self) -> None:
        runtime = self.root / "runtime"
        runtime.mkdir()
        digest = hashlib.sha256(self.wheel.read_bytes()).hexdigest()
        marker = runtime / "shieldmendai-runtime-installation.json"
        marker.write_text(
            json.dumps(
                {
                    "package_name": "shieldmendai",
                    "package_version": "0.4.0",
                    "wheel_sha256": digest,
                }
            ),
            encoding="utf-8",
        )
        bin_dir = runtime / "bin"
        bin_dir.mkdir()
        cli = bin_dir / "shieldmendai"
        cli.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        cli.chmod(0o750)
        with mock.patch("shieldmendai.dedicated_canary._run_process"):
            result = install_offline_runtime(self.wheel, runtime, apply=True)
        self.assertTrue(result.changed)

    def test_python_module_entrypoint_works(self) -> None:
        env = {**os.environ, "PYTHONPATH": str(SRC)}
        completed = subprocess.run(
            [sys.executable, "-m", "shieldmendai", "--help"],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ShieldMendAi", completed.stdout)


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
        self.assertNotIn("shell=True", module_text)
        self.assertNotIn("useradd", module_text)
        self.assertNotIn("groupadd", module_text)
        self.assertNotIn("systemctl", module_text)
        self.assertNotIn("requests", module_text)
        self.assertNotIn("urllib", module_text)


if __name__ == "__main__":
    unittest.main()
