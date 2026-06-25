from __future__ import annotations

import contextlib
import copy
import io
import json
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

import shieldmendai
from shieldmendai.cli import run
from shieldmendai.config import parse_config
from shieldmendai.errors import ConfigurationError
from shieldmendai.models import (
    Incident,
    NotificationChannelType,
    ReliabilityCategory,
    Severity,
    to_primitive,
)
from shieldmendai.planner import create_plan
from shieldmendai.redaction import redact


EXAMPLE = ROOT / "examples" / "shieldmendai.example.yaml"


def example_data() -> dict:
    with EXAMPLE.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def run_cli(*args: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = run(list(args))
    return code, stdout.getvalue(), stderr.getvalue()


class PackageAndCliTests(unittest.TestCase):
    def test_package_imports_and_version(self) -> None:
        self.assertEqual(shieldmendai.__version__, "0.2.0")

    def test_cli_version_works(self) -> None:
        with self.assertRaises(SystemExit) as result:
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                run(["--version"])
        self.assertEqual(result.exception.code, 0)
        self.assertIn("ShieldMendAi 0.2.0", stdout.getvalue())

    def test_valid_example_configuration_loads(self) -> None:
        code, stdout, stderr = run_cli("validate-config", str(EXAMPLE))
        self.assertEqual(code, 0)
        self.assertIn("Valid ShieldMendAi configuration", stdout)
        self.assertEqual(stderr, "")

    def test_invalid_configuration_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.yaml"
            path.write_text("global: {}\ntargets: []\n", encoding="utf-8")
            code, _, stderr = run_cli("validate-config", str(path))
        self.assertNotEqual(code, 0)
        self.assertIn("Configuration error", stderr)

    def test_yaml_error_does_not_echo_input(self) -> None:
        marker = "do-not-echo-this-marker"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.yaml"
            path.write_text(f"global: [\n  {marker}: value\n", encoding="utf-8")
            code, _, stderr = run_cli("validate-config", str(path))
        self.assertNotEqual(code, 0)
        self.assertNotIn(marker, stderr)

    def test_show_config_redacts_environment_references(self) -> None:
        code, stdout, _ = run_cli("show-config", str(EXAMPLE))
        self.assertEqual(code, 0)
        self.assertIn("<redacted-env-reference>", stdout)
        self.assertNotIn("SHIELDMENDAI_TELEGRAM_TOKEN", stdout)
        self.assertNotIn("SHIELDMENDAI_EMAIL_PASSWORD", stdout)
        self.assertNotIn("SHIELDMENDAI_SMS_FROM_NUMBER", stdout)
        self.assertNotIn("SHIELDMENDAI_SMS_RECIPIENT", stdout)

    def test_plan_is_clearly_dry_run(self) -> None:
        code, stdout, _ = run_cli("plan", str(EXAMPLE))
        self.assertEqual(code, 0)
        self.assertIn("DRY-RUN / PLANNING ONLY", stdout)
        self.assertIn('"planning_only": true', stdout)


class ConfigurationValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = example_data()

    def test_duplicate_target_ids_are_rejected(self) -> None:
        self.data["targets"].append(copy.deepcopy(self.data["targets"][0]))
        with self.assertRaisesRegex(ConfigurationError, "duplicate id"):
            parse_config(self.data)

    def test_empty_target_id_is_rejected(self) -> None:
        self.data["targets"][0]["id"] = ""
        with self.assertRaises(ConfigurationError):
            parse_config(self.data)

    def test_missing_names_are_rejected(self) -> None:
        self.data["global"]["application_name"] = ""
        with self.assertRaises(ConfigurationError):
            parse_config(self.data)

    def test_negative_timing_values_are_rejected(self) -> None:
        for key in (
            "poll_interval_seconds",
            "default_cooldown_seconds",
            "default_verification_delay_seconds",
        ):
            data = example_data()
            data["global"][key] = -1
            with self.subTest(key=key), self.assertRaises(ConfigurationError):
                parse_config(data)

    def test_invalid_retry_values_are_rejected(self) -> None:
        self.data["global"]["default_retry_limit"] = -1
        with self.assertRaises(ConfigurationError):
            parse_config(self.data)

    def test_phase_two_requires_dry_run(self) -> None:
        self.data["global"]["dry_run"] = False
        with self.assertRaises(ConfigurationError):
            parse_config(self.data)

    def test_invalid_policy_mode_is_rejected(self) -> None:
        self.data["repair_policies"][0]["mode"] = "fix_everything"
        with self.assertRaises(ConfigurationError):
            parse_config(self.data)

    def test_unsupported_adapter_type_is_rejected(self) -> None:
        self.data["targets"][0]["adapter_type"] = "magic_scanner"
        with self.assertRaises(ConfigurationError):
            parse_config(self.data)

    def test_invalid_port_is_rejected(self) -> None:
        tcp_target = next(item for item in self.data["targets"] if item["adapter_type"] == "tcp")
        tcp_target["monitoring"]["port"] = 70000
        with self.assertRaises(ConfigurationError):
            parse_config(self.data)

    def test_invalid_http_method_is_rejected(self) -> None:
        http_target = next(item for item in self.data["targets"] if item["adapter_type"] == "http")
        http_target["monitoring"]["method"] = "CONNECT"
        with self.assertRaises(ConfigurationError):
            parse_config(self.data)

    def test_direct_credential_values_are_rejected_without_echoing_value(self) -> None:
        marker = "do-not-display-this-value"
        telegram = next(
            item for item in self.data["notification_channels"] if item["type"] == "telegram"
        )
        telegram["settings"]["token"] = marker
        with self.assertRaises(ConfigurationError) as error:
            parse_config(self.data)
        self.assertNotIn(marker, str(error.exception))

    def test_authenticated_url_is_rejected_without_echoing_value(self) -> None:
        marker = "private-password-marker"
        http_target = next(item for item in self.data["targets"] if item["adapter_type"] == "http")
        http_target["monitoring"]["url"] = (
            "https" + "://" + "user" + ":" + marker + "@" + "example.invalid/health"
        )
        with self.assertRaises(ConfigurationError) as error:
            parse_config(self.data)
        self.assertNotIn(marker, str(error.exception))

    def test_executable_shell_string_is_rejected(self) -> None:
        target = next(
            item for item in self.data["targets"] if item["adapter_type"] == "executable_check"
        )
        target["monitoring"] = {"command": "/bin/check --all"}
        with self.assertRaises(ConfigurationError):
            parse_config(self.data)

    def test_executable_arguments_must_be_a_list(self) -> None:
        target = next(
            item for item in self.data["targets"] if item["adapter_type"] == "executable_check"
        )
        target["monitoring"]["arguments"] = "--format json"
        with self.assertRaises(ConfigurationError):
            parse_config(self.data)

    def test_private_source_reference_is_rejected(self) -> None:
        self.data["targets"][0]["monitoring"]["path"] = "/root/" + "newbasebot"
        with self.assertRaises(ConfigurationError):
            parse_config(self.data)

    def test_legacy_unit_prefix_is_rejected(self) -> None:
        self.data["targets"][0]["monitoring"]["unit"] = "new" + "base-example.service"
        with self.assertRaises(ConfigurationError):
            parse_config(self.data)

    def test_empty_service_and_timer_names_are_rejected(self) -> None:
        for adapter_type in ("systemd_service", "systemd_timer"):
            data = example_data()
            target = data["targets"][0]
            target["adapter_type"] = adapter_type
            target["monitoring"]["unit"] = ""
            with self.subTest(adapter_type=adapter_type), self.assertRaises(ConfigurationError):
                parse_config(data)

    def test_notification_models_use_environment_references(self) -> None:
        config = parse_config(self.data)
        telegram = next(
            item for item in config.notification_channels
            if item.channel_type is NotificationChannelType.TELEGRAM
        )
        self.assertTrue(telegram.settings["token_env"].endswith("_TOKEN"))
        self.assertNotIn("token", {key.lower() for key in telegram.settings})


class NoLiveOperationsTests(unittest.TestCase):
    def test_plan_performs_no_subprocess_network_or_systemd_access(self) -> None:
        config = parse_config(example_data())
        with (
            mock.patch.object(subprocess, "run", side_effect=AssertionError("subprocess called")),
            mock.patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess called")),
            mock.patch.object(socket, "create_connection", side_effect=AssertionError("network called")),
            mock.patch("urllib.request.urlopen", side_effect=AssertionError("HTTP called")),
        ):
            plan = create_plan(config)
        self.assertTrue(plan.planning_only)
        self.assertTrue(plan.dry_run)

    def test_no_notification_or_repair_adapter_is_invoked(self) -> None:
        config = parse_config(example_data())
        plan = create_plan(config)
        self.assertGreater(len(plan.targets), 0)
        self.assertFalse(any(hasattr(target, "execute") for target in plan.targets))

    def test_tests_write_only_to_temporary_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(yaml.safe_dump(example_data()), encoding="utf-8")
            code, _, _ = run_cli("validate-config", str(path))
            self.assertEqual(code, 0)


class ModelsAndRepositoryTests(unittest.TestCase):
    def test_incident_serializes_without_secrets(self) -> None:
        incident = Incident.planning_record(
            incident_id="incident-example",
            application_id="application-example",
            target_id="target-example",
            category=ReliabilityCategory.SERVICE_FAILED,
            severity=Severity.HIGH,
        )
        value = incident.to_safe_dict()
        serialized = json.dumps(value)
        self.assertNotIn("password", serialized.lower())
        self.assertNotIn("private_key", serialized.lower())
        self.assertEqual(value["detection_source"], "planning_only")

    def test_plugin_and_code_repair_models_are_data_only(self) -> None:
        from shieldmendai.models import (
            CodeRepairStage,
            CodeRepairWorkflow,
            PluginCapability,
            PluginRequest,
        )

        plugin_request = PluginRequest(
            schema_version="1.0",
            request_id="request-example",
            capability=PluginCapability.OBSERVE,
            target_id="target-example",
            sanitized_parameters={},
            timeout_seconds=5,
        )
        workflow = CodeRepairWorkflow(
            repository_reference="approved-repository",
            approved_branch="approved-branch",
            preserved_commit="commit-id",
            deployment_version="version-id",
            current_stage=CodeRepairStage.FAILURE_REPRODUCED,
            required_checks=("tests", "linters", "type_checks"),
        )
        self.assertEqual(to_primitive(plugin_request)["capability"], "observe")
        self.assertTrue(workflow.customer_approval_required)
        self.assertFalse(hasattr(plugin_request, "execute"))

    def test_redaction_handles_sensitive_fields(self) -> None:
        value = redact(
            {
                "token": "sensitive",
                "password_env": "PASSWORD_REFERENCE",
                "url": (
                    "https" + "://" + "user" + ":" + "password" + "@"
                    + "example.invalid/health"
                ),
            }
        )
        serialized = json.dumps(value)
        self.assertNotIn("sensitive", serialized)
        self.assertNotIn("PASSWORD_REFERENCE", serialized)
        self.assertNotIn("user:password", serialized)

    def test_implementation_has_no_private_or_legacy_references(self) -> None:
        forbidden_path = "/root/" + "newbasebot"
        forbidden_unit = "new" + "base-"
        for path in (ROOT / "src").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertNotIn(forbidden_path, text)
                self.assertNotIn(forbidden_unit, text)
                self.assertNotIn("shell=True", text)
                self.assertNotIn("eval(", text)
                self.assertNotIn("exec(", text)

    def test_public_product_naming(self) -> None:
        for path in (ROOT / "src").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertNotIn("Guardian", text)
        self.assertEqual(shieldmendai.__version__, "0.2.0")

    def test_example_is_language_independent(self) -> None:
        data = example_data()
        adapter_types = {item["adapter_type"] for item in data["targets"]}
        tags = {tag for item in data["targets"] for tag in item.get("tags", [])}
        self.assertTrue({"systemd_service", "http", "tcp", "json_file", "executable_check"} <= adapter_types)
        self.assertTrue({"nodejs", "java", "language-independent"} <= tags)
        serialized = yaml.safe_dump(data)
        self.assertNotIn("/root/" + "newbasebot", serialized)
        self.assertNotIn("new" + "base-", serialized)
        self.assertNotIn("wallet", serialized.lower())
        self.assertNotIn("trading", serialized.lower())


if __name__ == "__main__":
    unittest.main()
