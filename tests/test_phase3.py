from __future__ import annotations

import contextlib
import hashlib
import io
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

from shieldmendai.cli import run
from shieldmendai.config import parse_config
from shieldmendai.errors import AdapterError, ScenarioError, UnsafeObservationError
from shieldmendai.fixture_paths import resolve_fixture_path, validate_fixture_root
from shieldmendai.models import (
    AdapterType,
    ObservationStatus,
    ReliabilityCategory,
)
from shieldmendai.observation import (
    AdapterRegistry,
    ObservationCoordinator,
    StateSimulationAdapter,
    build_simulation_registry,
)
from shieldmendai.scenarios import parse_scenario

SIM_CONFIG = ROOT / "examples" / "simulation-config.yaml"
SIM_SCENARIO = ROOT / "examples" / "scenarios" / "phase3-example.yaml"


def config_data() -> dict:
    return yaml.safe_load(SIM_CONFIG.read_text(encoding="utf-8"))


def scenario_for(target_id: str, adapter_type: str, state: str, **data: object) -> dict:
    return {
        "schema_version": "1.0",
        "observed_at": "2030-01-01T00:00:00Z",
        "targets": [{
            "target_id": target_id,
            "adapter_type": adapter_type,
            "state": state,
            "duration_ms": 1,
            "data": data,
        }],
    }


def run_cli(*args: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = run(list(args))
    return code, stdout.getvalue(), stderr.getvalue()


class RegistryTests(unittest.TestCase):
    def test_registry_accepts_valid_adapter_and_returns_capabilities(self) -> None:
        registry = AdapterRegistry()
        adapter = StateSimulationAdapter(AdapterType.HTTP, ("states",))
        registry.register(adapter)
        self.assertIs(registry.get(AdapterType.HTTP), adapter)
        self.assertEqual(registry.capabilities()[0].adapter_type, AdapterType.HTTP)

    def test_duplicate_registration_is_rejected(self) -> None:
        registry = AdapterRegistry()
        registry.register(StateSimulationAdapter(AdapterType.HTTP, ("states",)))
        with self.assertRaises(AdapterError):
            registry.register(StateSimulationAdapter(AdapterType.HTTP, ("states",)))

    def test_unknown_adapter_is_rejected(self) -> None:
        with self.assertRaises(AdapterError):
            AdapterRegistry().get(AdapterType.HTTP)

    def test_all_phase3_adapters_are_simulation_only(self) -> None:
        capabilities = build_simulation_registry().capabilities()
        self.assertEqual(len(capabilities), 11)
        for item in capabilities:
            self.assertTrue(item.supports_simulation)
            self.assertFalse(item.production_available)
            self.assertFalse(item.requires_network)
            self.assertFalse(item.requires_subprocess)
            self.assertFalse(item.requires_privileged_access)


class StateMappingTests(unittest.TestCase):
    def _observe(self, target_id: str, adapter: str, state: str):
        config = parse_config(config_data())
        scenario = parse_scenario(scenario_for(target_id, adapter, state))
        return ObservationCoordinator(build_simulation_registry()).run(config, scenario)[0]

    def test_healthy_service(self) -> None:
        self.assertEqual(
            self._observe("healthy-service", "systemd_service", "active").status,
            ObservationStatus.HEALTHY,
        )

    def test_failed_service(self) -> None:
        result = self._observe("failed-service", "systemd_service", "failed")
        self.assertEqual(result.findings[0].category, ReliabilityCategory.SERVICE_FAILED)

    def test_inactive_service(self) -> None:
        result = self._observe("healthy-service", "systemd_service", "inactive")
        self.assertEqual(result.findings[0].category, ReliabilityCategory.SERVICE_STOPPED)

    def test_restart_loop(self) -> None:
        result = self._observe("restart-loop", "systemd_service", "restart_loop")
        self.assertEqual(result.findings[0].category, ReliabilityCategory.RESTART_LOOP)

    def test_missing_process(self) -> None:
        result = self._observe("missing-process", "process", "missing")
        self.assertEqual(result.findings[0].category, ReliabilityCategory.PROCESS_MISSING)

    def test_http_failure(self) -> None:
        result = self._observe("unhealthy-http", "http", "timeout")
        self.assertEqual(result.findings[0].category, ReliabilityCategory.HTTP_UNHEALTHY)

    def test_tcp_failure(self) -> None:
        result = self._observe("java-tcp", "tcp", "refused")
        self.assertEqual(result.findings[0].category, ReliabilityCategory.TCP_UNREACHABLE)

    def test_executable_timeout_is_data_only(self) -> None:
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("called")):
            result = self._observe("executable-timeout", "executable_check", "timeout")
        self.assertEqual(result.findings[0].category, ReliabilityCategory.APPLICATION_TEST_FAILURE)


class FixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "fixtures"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _observe(
        self,
        adapter: str,
        filename: str,
        content: str | None,
        **data: object,
    ):
        config_value = config_data()
        target = next(item for item in config_value["targets"] if item["id"] == "valid-json")
        target["adapter_type"] = adapter
        target["monitoring"] = {"path": filename, "required": True}
        if content is not None and not (self.root / filename).exists():
            (self.root / filename).write_text(content, encoding="utf-8")
        raw = scenario_for("valid-json", adapter, "fixture", fixture_path=filename, **data)
        raw["fixture_root"] = str(self.root)
        return ObservationCoordinator(build_simulation_registry()).run(
            parse_config(config_value), parse_scenario(raw)
        )[0]

    def test_missing_fixture(self) -> None:
        result = self._observe("file", "missing.txt", None)
        self.assertEqual(result.findings[0].category, ReliabilityCategory.FILE_MISSING)

    def test_stale_fixture(self) -> None:
        result = self._observe(
            "file", "stale.txt", "old", freshness_threshold_seconds=1
        )
        self.assertEqual(result.findings[0].category, ReliabilityCategory.FILE_STALE)

    def test_invalid_json_yaml_and_toml(self) -> None:
        cases = (
            ("json_file", "bad.json", "{", ReliabilityCategory.INVALID_JSON),
            ("yaml_file", "bad.yaml", "value: [", ReliabilityCategory.INVALID_YAML),
            ("toml_file", "bad.toml", "value = [", ReliabilityCategory.INVALID_TOML),
        )
        for adapter, filename, content, category in cases:
            with self.subTest(adapter=adapter):
                result = self._observe(adapter, filename, content)
                self.assertEqual(result.findings[0].category, category)

    def test_permission_mismatch(self) -> None:
        result = self._observe("file", "mode.txt", "data", expected_permissions="0600")
        self.assertEqual(result.findings[0].category, ReliabilityCategory.INCORRECT_PERMISSIONS)

    def test_checksum_mismatch(self) -> None:
        result = self._observe("file", "sum.txt", "data", expected_sha256="0" * 64)
        self.assertEqual(result.findings[0].category, ReliabilityCategory.UNEXPECTED_FILE_CHANGE)

    def test_valid_structured_fixtures(self) -> None:
        values = (
            ("json_file", "good.json", '{"ok": true}'),
            ("yaml_file", "good.yaml", "ok: true\n"),
            ("toml_file", "good.toml", "ok = true\n"),
        )
        for adapter, filename, content in values:
            with self.subTest(adapter=adapter):
                result = self._observe(adapter, filename, content)
                self.assertEqual(result.status, ObservationStatus.HEALTHY)

    def test_valid_checksum(self) -> None:
        content = "unchanged"
        digest = hashlib.sha256(content.encode()).hexdigest()
        result = self._observe("file", "sum.txt", content, expected_sha256=digest)
        self.assertEqual(result.status, ObservationStatus.HEALTHY)

    def test_path_traversal_is_rejected(self) -> None:
        with self.assertRaises(UnsafeObservationError):
            resolve_fixture_path(self.root, "../escape.txt")

    def test_symlink_escape_is_rejected(self) -> None:
        outside = Path(self.temporary.name) / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        (self.root / "escape.txt").symlink_to(outside)
        with self.assertRaises(UnsafeObservationError):
            resolve_fixture_path(self.root, "escape.txt")

    def test_absolute_server_path_is_rejected(self) -> None:
        with self.assertRaises(UnsafeObservationError):
            validate_fixture_root("/etc")

    def test_private_source_root_is_rejected_before_resolution(self) -> None:
        with mock.patch.object(Path, "resolve", side_effect=AssertionError("resolved")):
            with self.assertRaises(UnsafeObservationError):
                validate_fixture_root("/root/" + "newbasebot")

    def test_observation_does_not_modify_fixture(self) -> None:
        path = self.root / "stable.json"
        path.write_text('{"ok": true}', encoding="utf-8")
        before = (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
        self._observe("json_file", "stable.json", '{"ok": true}')
        after = (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
        self.assertEqual(before, after)


class ScenarioAndCliTests(unittest.TestCase):
    def test_unknown_target_and_adapter_mismatch_are_rejected(self) -> None:
        config = parse_config(config_data())
        unknown = parse_scenario(scenario_for("unknown", "http", "healthy"))
        with self.assertRaises(ScenarioError):
            ObservationCoordinator(build_simulation_registry()).run(config, unknown)
        mismatch = parse_scenario(scenario_for("node-api", "tcp", "reachable"))
        with self.assertRaises(ScenarioError):
            ObservationCoordinator(build_simulation_registry()).run(config, mismatch)

    def test_duplicate_ids_unknown_states_and_negative_duration_are_rejected(self) -> None:
        base = scenario_for("node-api", "http", "healthy")
        duplicate = json.loads(json.dumps(base))
        duplicate["targets"].append(dict(duplicate["targets"][0]))
        with self.assertRaises(ScenarioError):
            parse_scenario(duplicate)
        bad_state = scenario_for("node-api", "http", "live_request")
        with self.assertRaises(ScenarioError):
            parse_scenario(bad_state)
        negative = scenario_for("node-api", "http", "healthy")
        negative["targets"][0]["duration_ms"] = -1
        with self.assertRaises(ScenarioError):
            parse_scenario(negative)

    def test_invalid_timestamp_and_credentials_are_rejected(self) -> None:
        invalid = scenario_for("node-api", "http", "healthy")
        invalid["observed_at"] = "not-a-time"
        with self.assertRaises(ScenarioError):
            parse_scenario(invalid)
        credential = scenario_for(
            "node-api", "http", "healthy", token="do-not-store-this"
        )
        with self.assertRaises(ScenarioError) as error:
            parse_scenario(credential)
        self.assertNotIn("do-not-store-this", str(error.exception))

    def test_evidence_is_redacted(self) -> None:
        with self.assertRaises(ScenarioError):
            parse_scenario(
                scenario_for("node-api", "http", "healthy", username_env="REFERENCE")
            )

    def test_list_and_inspect_output_are_clearly_safe(self) -> None:
        code, output, _ = run_cli("list-adapters")
        self.assertEqual(code, 0)
        self.assertIn("SIMULATION ONLY", output)
        self.assertIn('"production_available": false', output)
        code, output, _ = run_cli("inspect-scenario", str(SIM_SCENARIO))
        self.assertEqual(code, 0)
        self.assertIn("NO ADAPTER EXECUTION", output)

    def test_simulation_exit_codes(self) -> None:
        healthy = scenario_for("healthy-service", "systemd_service", "active")
        unhealthy = scenario_for("failed-service", "systemd_service", "failed")
        invalid = scenario_for("failed-service", "systemd_service", "not-real")
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index, value in enumerate((healthy, unhealthy, invalid)):
                path = Path(directory) / f"{index}.yaml"
                path.write_text(yaml.safe_dump(value), encoding="utf-8")
                paths.append(path)
            code, output, _ = run_cli("simulate", str(SIM_CONFIG), str(paths[0]))
            self.assertEqual(code, 0)
            self.assertIn("SIMULATION ONLY", output)
            self.assertEqual(run_cli("simulate", str(SIM_CONFIG), str(paths[1]))[0], 2)
            self.assertEqual(run_cli("simulate", str(SIM_CONFIG), str(paths[2]))[0], 1)

    def test_simulation_has_no_live_or_action_boundaries(self) -> None:
        with (
            mock.patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
            mock.patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
            mock.patch.object(os, "system", side_effect=AssertionError("system")),
            mock.patch.object(socket, "create_connection", side_effect=AssertionError("socket")),
            mock.patch.object(socket.socket, "connect", side_effect=AssertionError("socket")),
            mock.patch("urllib.request.urlopen", side_effect=AssertionError("http")),
        ):
            code, _, _ = run_cli("simulate", str(SIM_CONFIG), str(SIM_SCENARIO))
        self.assertEqual(code, 2)

    def test_no_repair_notification_or_systemd_implementation_exists(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8") for path in (ROOT / "src" / "shieldmendai").glob("*.py")
        )
        for prohibited in (
            "subprocess.run(", "subprocess.Popen(", "socket.connect(",
            "urlopen(", "systemctl ", "dbus.SystemBus(", ".deliver(",
            ".restart(", "shell=True",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, source)


if __name__ == "__main__":
    unittest.main()
