from __future__ import annotations

import contextlib
import copy
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
from shieldmendai.errors import RepairValidationError, UnsafeRepairError
from shieldmendai.models import (
    ActionRisk,
    ApprovalDecision,
    AuthorizationReasonCode,
    PolicyMode,
    RepairActionCategory,
    SimulatedRepairOutcome,
    to_primitive,
)
from shieldmendai.repair import (
    ACTION_RISKS,
    SimulationRepairExecutor,
    authorization_context,
    authorize_repair,
    create_repair_plan,
    parse_repair_input,
    parse_repair_policy,
    parse_repair_scenario,
)

REPAIR_ROOT = ROOT / "examples" / "repair"
CONFIG = REPAIR_ROOT / "config.yaml"
REQUEST = REPAIR_ROOT / "request.yaml"
POLICY = REPAIR_ROOT / "policy.yaml"
SUCCESS = REPAIR_ROOT / "scenarios" / "success.yaml"
VERIFY_FAIL = REPAIR_ROOT / "scenarios" / "verification-failure.yaml"
ROLLBACK_FAIL = REPAIR_ROOT / "scenarios" / "rollback-failure.yaml"


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def run_cli(*args: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = run(list(args))
    return code, stdout.getvalue(), stderr.getvalue()


class RepairHarness:
    def __init__(self) -> None:
        self.config_data = load_yaml(CONFIG)
        self.request_data = load_yaml(REQUEST)
        self.policy_data = load_yaml(POLICY)

    def policy(self):
        return parse_repair_policy(self.policy_data)

    def repair_input(self):
        return parse_repair_input(self.request_data)

    def authorize(self):
        config = parse_config(self.config_data)
        repair_input = self.repair_input()
        policy = self.policy()
        context = authorization_context(config, repair_input, policy)
        decision = authorize_repair(repair_input.request, context)
        return repair_input, context, decision

    def configure_action(
        self,
        action: str,
        *,
        target_id: str = "fictional-api-service",
        adapter: str = "systemd_service",
        category: str = "service_failed",
        maximum_risk: str | None = None,
        rollback: bool = True,
    ) -> None:
        request = self.request_data["request"]
        request["requested_action"] = action
        request["target_id"] = target_id
        request["adapter_type"] = adapter
        request["finding_category"] = category
        approval = self.request_data["approval"]
        approval["approved_action"] = action
        approval["target_scope"] = [target_id]
        verification = self.request_data["verification_plan"]
        verification["target_id"] = target_id
        verification["adapter_type"] = adapter
        policy = self.policy_data["policy"]
        policy["allowed_actions"] = [action]
        policy["allowed_target_ids"] = [target_id]
        policy["allowed_adapter_types"] = [adapter]
        policy["allowed_target_actions"] = [{"target_id": target_id, "action": action}]
        policy["allowed_finding_categories"] = [category]
        if maximum_risk:
            policy["maximum_risk"] = maximum_risk
        if rollback:
            self.request_data["rollback_plan"]["original_action"] = action
            if action == "restore_known_good_file":
                self.request_data["rollback_plan"]["known_good_reference"] = "fixture-known-good-001"
        else:
            self.request_data.pop("rollback_plan", None)


class PolicyValidationTests(unittest.TestCase):
    def test_unknown_action_policy_mode_and_risk_are_rejected(self) -> None:
        for field, value in (
            ("allowed_actions", ["not_an_action"]),
            ("mode", "unrestricted"),
            ("maximum_risk", "unknown"),
        ):
            harness = RepairHarness()
            harness.policy_data["policy"][field] = value
            with self.subTest(field=field), self.assertRaises(RepairValidationError):
                harness.policy()

    def test_wildcards_duplicates_and_contradictory_pairs_are_rejected(self) -> None:
        cases = []
        wildcard_target = RepairHarness()
        wildcard_target.policy_data["policy"]["allowed_target_ids"] = ["*"]
        cases.append(wildcard_target)
        wildcard_action = RepairHarness()
        wildcard_action.policy_data["policy"]["allowed_actions"] = ["*"]
        cases.append(wildcard_action)
        duplicate = RepairHarness()
        duplicate.policy_data["policy"]["allowed_target_ids"] *= 2
        cases.append(duplicate)
        contradictory = RepairHarness()
        contradictory.policy_data["policy"]["allowed_target_actions"][0]["target_id"] = "other"
        cases.append(contradictory)
        for index, harness in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(RepairValidationError):
                harness.policy()

    def test_unknown_action_request_and_invalid_scenario_data_are_rejected(self) -> None:
        harness = RepairHarness()
        harness.request_data["request"]["requested_action"] = "not_an_action"
        with self.assertRaises(RepairValidationError):
            harness.repair_input()
        scenario = load_yaml(SUCCESS)
        scenario["verification_outcome"] = "live_check"
        with self.assertRaises(RepairValidationError):
            parse_repair_scenario(scenario)

    def test_credential_personal_and_command_like_values_are_rejected(self) -> None:
        cases = []
        token = RepairHarness()
        token.request_data["token"] = "secret-value"
        cases.append(token)
        email = RepairHarness()
        email.request_data["approval"]["approver_reference"] = "person@example.invalid"
        cases.append(email)
        command = RepairHarness()
        command.request_data["shell_command"] = "unsafe value"
        cases.append(command)
        for index, harness in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(RepairValidationError):
                harness.repair_input()


class AuthorizationTests(unittest.TestCase):
    def _reason_codes(self, harness: RepairHarness) -> set[AuthorizationReasonCode]:
        return {item.code for item in harness.authorize()[2].reasons}

    def test_valid_matching_approval_permits_simulation(self) -> None:
        _, _, decision = RepairHarness().authorize()
        self.assertTrue(decision.permitted)
        self.assertEqual(
            [item.code for item in decision.reasons],
            [AuthorizationReasonCode.AUTHORIZED],
        )

    def test_empty_allowlists_and_unknown_target_deny(self) -> None:
        empty = RepairHarness()
        policy = empty.policy_data["policy"]
        policy["allowed_target_ids"] = []
        policy["allowed_adapter_types"] = []
        policy["allowed_actions"] = []
        policy["allowed_target_actions"] = []
        self.assertFalse(empty.authorize()[2].permitted)
        unknown = RepairHarness()
        unknown.request_data["request"]["target_id"] = "unknown-target"
        unknown.request_data["approval"]["target_scope"] = ["unknown-target"]
        unknown.request_data["verification_plan"]["target_id"] = "unknown-target"
        self.assertIn(AuthorizationReasonCode.TARGET_NOT_FOUND, self._reason_codes(unknown))

    def test_observe_only_and_recommend_never_execute(self) -> None:
        observe = RepairHarness()
        observe.policy_data["policy"]["mode"] = PolicyMode.OBSERVE_ONLY.value
        self.assertIn(
            AuthorizationReasonCode.POLICY_OBSERVE_ONLY,
            self._reason_codes(observe),
        )
        recommend = RepairHarness()
        recommend.policy_data["policy"]["mode"] = PolicyMode.RECOMMEND.value
        decision = recommend.authorize()[2]
        self.assertFalse(decision.permitted)
        self.assertTrue(decision.recommendation_only)
        self.assertIn(
            AuthorizationReasonCode.POLICY_RECOMMEND_ONLY,
            {item.code for item in decision.reasons},
        )

    def test_approval_missing_expired_revoked_and_consumed_deny(self) -> None:
        missing = RepairHarness()
        missing.request_data.pop("approval")
        expired = RepairHarness()
        expired.request_data["approval"]["expires_at"] = "2029-12-31T23:59:00Z"
        revoked = RepairHarness()
        revoked.request_data["approval"]["decision"] = ApprovalDecision.REVOKED.value
        revoked.request_data["approval"]["revoked"] = True
        consumed = RepairHarness()
        consumed.request_data["approval"]["consumed_at"] = "2030-01-01T00:00:45Z"
        expected = (
            (missing, AuthorizationReasonCode.APPROVAL_MISSING),
            (expired, AuthorizationReasonCode.APPROVAL_EXPIRED),
            (revoked, AuthorizationReasonCode.APPROVAL_REVOKED),
            (consumed, AuthorizationReasonCode.APPROVAL_CONSUMED),
        )
        for harness, code in expected:
            with self.subTest(code=code):
                self.assertIn(code, self._reason_codes(harness))

    def test_mismatched_approval_request_action_and_target_deny(self) -> None:
        cases = []
        request = RepairHarness()
        request.request_data["approval"]["request_id"] = "other-request"
        cases.append(request)
        action = RepairHarness()
        action.request_data["approval"]["approved_action"] = "no_action"
        cases.append(action)
        target = RepairHarness()
        target.request_data["approval"]["target_scope"] = ["other-target"]
        cases.append(target)
        for index, harness in enumerate(cases):
            with self.subTest(index=index):
                self.assertIn(
                    AuthorizationReasonCode.APPROVAL_INVALID,
                    self._reason_codes(harness),
                )

    def test_target_action_adapter_and_finding_mismatches_deny(self) -> None:
        target = RepairHarness()
        target.policy_data["policy"]["allowed_target_ids"] = ["fictional-config-file"]
        target.policy_data["policy"]["allowed_target_actions"][0]["target_id"] = "fictional-config-file"
        action = RepairHarness()
        action.policy_data["policy"]["allowed_actions"] = ["no_action"]
        action.policy_data["policy"]["allowed_target_actions"][0]["action"] = "no_action"
        adapter = RepairHarness()
        adapter.request_data["request"]["adapter_type"] = "file"
        adapter.request_data["verification_plan"]["adapter_type"] = "file"
        finding = RepairHarness()
        finding.request_data["request"]["finding_category"] = "file_missing"
        expected = (
            (target, AuthorizationReasonCode.TARGET_NOT_ALLOWLISTED),
            (action, AuthorizationReasonCode.ACTION_NOT_ALLOWLISTED),
            (adapter, AuthorizationReasonCode.ADAPTER_MISMATCH),
            (finding, AuthorizationReasonCode.FINDING_ACTION_MISMATCH),
        )
        for harness, code in expected:
            with self.subTest(code=code):
                self.assertIn(code, self._reason_codes(harness))

    def test_risk_retry_cooldown_evidence_verification_and_rollback_gates(self) -> None:
        risk = RepairHarness()
        risk.configure_action(
            "apply_allowlisted_permission_fix",
            target_id="fictional-config-file",
            adapter="file",
            category="incorrect_permissions",
            maximum_risk="low",
        )
        retry = RepairHarness()
        retry.request_data["retry_state"]["attempts"] = 1
        cooldown = RepairHarness()
        cooldown.request_data["cooldown_state"]["elapsed"] = False
        evidence = RepairHarness()
        evidence.request_data["evidence_present"] = False
        verification = RepairHarness()
        verification.request_data.pop("verification_plan")
        rollback = RepairHarness()
        rollback.request_data.pop("rollback_plan")
        expected = (
            (risk, AuthorizationReasonCode.RISK_TOO_HIGH),
            (retry, AuthorizationReasonCode.RETRY_LIMIT_EXCEEDED),
            (cooldown, AuthorizationReasonCode.COOLDOWN_NOT_ELAPSED),
            (evidence, AuthorizationReasonCode.EVIDENCE_MISSING),
            (verification, AuthorizationReasonCode.VERIFICATION_MISSING),
            (rollback, AuthorizationReasonCode.ROLLBACK_MISSING),
        )
        for harness, code in expected:
            with self.subTest(code=code):
                self.assertIn(code, self._reason_codes(harness))

    def test_expired_consumed_and_production_requests_deny(self) -> None:
        expired = RepairHarness()
        expired.request_data["request"]["expires_at"] = "2030-01-01T00:00:59Z"
        consumed = RepairHarness()
        consumed.request_data["request"]["consumed_at"] = "2030-01-01T00:00:30Z"
        production = RepairHarness()
        production.request_data["request"]["simulation"] = False
        expected = (
            (expired, AuthorizationReasonCode.REQUEST_EXPIRED),
            (consumed, AuthorizationReasonCode.REQUEST_CONSUMED),
            (production, AuthorizationReasonCode.SIMULATION_REQUIRED),
        )
        for harness, code in expected:
            with self.subTest(code=code):
                self.assertIn(code, self._reason_codes(harness))

    def test_code_patch_is_prohibited_and_unknown_risk_defaults_prohibited(self) -> None:
        harness = RepairHarness()
        harness.configure_action(
            "apply_approved_code_patch",
            maximum_risk="prohibited",
            rollback=False,
        )
        self.assertIn(
            AuthorizationReasonCode.ACTION_PROHIBITED,
            self._reason_codes(harness),
        )
        self.assertIs(
            ACTION_RISKS.get(object(), ActionRisk.PROHIBITED),
            ActionRisk.PROHIBITED,
        )

    def test_explanations_are_structured_and_sanitized(self) -> None:
        harness = RepairHarness()
        harness.request_data.pop("approval")
        decision = harness.authorize()[2]
        serialized = json.dumps(decision.to_safe_dict()).lower()
        self.assertIn("approval_missing", serialized)
        for marker in ("password", "private_key", "secret-value"):
            self.assertNotIn(marker, serialized)


class PlanningAndSimulationTests(unittest.TestCase):
    def _plan(self, harness: RepairHarness):
        repair_input, context, decision = harness.authorize()
        self.assertTrue(decision.permitted, to_primitive(decision))
        return create_repair_plan(repair_input.request, context, decision)

    def _execute(self, harness: RepairHarness, scenario_path: Path):
        return SimulationRepairExecutor().execute(
            self._plan(harness),
            parse_repair_scenario(load_yaml(scenario_path)),
        )

    def test_supported_actions_simulate_without_live_changes(self) -> None:
        cases = (
            ("no_action", "fictional-api-service", "systemd_service", "service_failed", "informational", False),
            ("collect_evidence", "fictional-api-service", "systemd_service", "service_failed", "informational", False),
            ("notify_only", "fictional-api-service", "systemd_service", "service_failed", "informational", False),
            ("restart_allowlisted_service", "fictional-api-service", "systemd_service", "service_failed", "low", True),
            ("restore_known_good_file", "fictional-config-file", "file", "file_missing", "low", True),
            ("apply_allowlisted_permission_fix", "fictional-config-file", "file", "incorrect_permissions", "medium", True),
            ("rollback_deployment", "fictional-deployment", "plugin", "deployment_failure", "medium", True),
            ("request_manual_intervention", "fictional-api-service", "systemd_service", "service_failed", "informational", False),
        )
        for action, target, adapter, category, risk, rollback in cases:
            harness = RepairHarness()
            harness.configure_action(
                action,
                target_id=target,
                adapter=adapter,
                category=category,
                maximum_risk=risk,
                rollback=rollback,
            )
            with self.subTest(action=action):
                result = self._execute(harness, SUCCESS)
                self.assertTrue(result.simulation)
                self.assertFalse(result.production_execution_available)
                self.assertEqual(
                    result.outcome,
                    SimulatedRepairOutcome.AUTHORIZED_AND_SIMULATED_SUCCESS,
                )

    def test_verification_failure_triggers_simulated_rollback(self) -> None:
        result = self._execute(RepairHarness(), VERIFY_FAIL)
        self.assertEqual(
            result.rollback_outcome,
            SimulatedRepairOutcome.SIMULATED_ROLLBACK_SUCCESS.value,
        )
        self.assertEqual(
            result.outcome,
            SimulatedRepairOutcome.AUTHORIZED_AND_SIMULATED_FAILURE,
        )

    def test_rollback_failure_requires_manual_intervention(self) -> None:
        result = self._execute(RepairHarness(), ROLLBACK_FAIL)
        self.assertTrue(result.manual_intervention_required)
        self.assertEqual(
            result.outcome,
            SimulatedRepairOutcome.MANUAL_INTERVENTION_REQUIRED,
        )

    def test_executor_rejects_expired_or_mismatched_plan(self) -> None:
        harness = RepairHarness()
        plan = self._plan(harness)
        scenario = parse_repair_scenario(load_yaml(SUCCESS))
        expired = copy.deepcopy(load_yaml(SUCCESS))
        expired["observed_at"] = "2030-01-01T02:00:00Z"
        with self.assertRaises(UnsafeRepairError):
            SimulationRepairExecutor().execute(plan, parse_repair_scenario(expired))
        denied = copy.deepcopy(plan)
        object.__setattr__(denied.authorization, "permitted", False)
        with self.assertRaises(UnsafeRepairError):
            SimulationRepairExecutor().execute(denied, scenario)

    def test_no_monitored_file_or_permission_is_modified(self) -> None:
        harness = RepairHarness()
        harness.configure_action(
            "restore_known_good_file",
            target_id="fictional-config-file",
            adapter="file",
            category="file_missing",
            maximum_risk="low",
        )
        with tempfile.TemporaryDirectory() as directory:
            monitored = Path(directory) / "monitored.txt"
            monitored.write_text("unchanged", encoding="utf-8")
            before = (monitored.read_bytes(), monitored.stat().st_mode, monitored.stat().st_mtime_ns)
            self._execute(harness, SUCCESS)
            after = (monitored.read_bytes(), monitored.stat().st_mode, monitored.stat().st_mtime_ns)
        self.assertEqual(before, after)

    def test_audit_records_are_sanitized(self) -> None:
        result = self._execute(RepairHarness(), SUCCESS)
        serialized = json.dumps(result.audit_events[0].to_safe_dict()).lower()
        self.assertIn("simulation", serialized)
        for marker in ("password", "private_key", "token", "person@"):
            self.assertNotIn(marker, serialized)


class CliAndSafetyTests(unittest.TestCase):
    def test_repair_cli_labels_and_exit_codes(self) -> None:
        code, output, _ = run_cli("list-repair-actions")
        self.assertEqual(code, 0)
        self.assertIn("PRODUCTION REPAIR EXECUTION IS UNAVAILABLE", output)
        code, output, _ = run_cli(
            "plan-repair", str(CONFIG), str(REQUEST), str(POLICY)
        )
        self.assertEqual(code, 0)
        self.assertIn("SIMULATION PLANNING ONLY — NO SYSTEM CHANGES", output)
        code, output, _ = run_cli(
            "simulate-repair", str(CONFIG), str(REQUEST), str(POLICY), str(SUCCESS)
        )
        self.assertEqual(code, 0)
        self.assertIn("SIMULATION ONLY — NO LIVE REPAIR PERFORMED", output)
        self.assertEqual(
            run_cli(
                "simulate-repair",
                str(CONFIG),
                str(REQUEST),
                str(POLICY),
                str(VERIFY_FAIL),
            )[0],
            3,
        )
        self.assertEqual(
            run_cli(
                "simulate-repair",
                str(CONFIG),
                str(REQUEST),
                str(POLICY),
                str(ROLLBACK_FAIL),
            )[0],
            5,
        )

    def test_cli_denial_exit_code(self) -> None:
        request = load_yaml(REQUEST)
        request.pop("approval")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "denied.yaml"
            path.write_text(yaml.safe_dump(request), encoding="utf-8")
            code, output, _ = run_cli(
                "authorize-repair", str(CONFIG), str(path), str(POLICY)
            )
        self.assertEqual(code, 2)
        self.assertIn("approval_missing", output)

    def test_simulation_calls_no_live_boundaries(self) -> None:
        with (
            mock.patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
            mock.patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
            mock.patch.object(os, "system", side_effect=AssertionError("system")),
            mock.patch.object(os, "chmod", side_effect=AssertionError("chmod")),
            mock.patch.object(os, "chown", side_effect=AssertionError("chown")),
            mock.patch.object(socket, "create_connection", side_effect=AssertionError("socket")),
            mock.patch.object(socket.socket, "connect", side_effect=AssertionError("socket")),
            mock.patch("urllib.request.urlopen", side_effect=AssertionError("http")),
        ):
            code, _, _ = run_cli(
                "simulate-repair", str(CONFIG), str(REQUEST), str(POLICY), str(SUCCESS)
            )
        self.assertEqual(code, 0)

    def test_implementation_contains_no_production_operation_calls(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "src" / "shieldmendai").glob("*.py")
        )
        prohibited = (
            "subprocess.run(",
            "subprocess.Popen(",
            "os.system(",
            "socket.connect(",
            "urlopen(",
            "systemctl ",
            "dbus.SystemBus(",
            "os.chmod(",
            "os.chown(",
            ".restart(",
            ".deliver(",
            "git clone",
            "git checkout",
            "shell=True",
        )
        for value in prohibited:
            with self.subTest(value=value):
                self.assertNotIn(value, source)

    def test_private_and_legacy_names_are_absent_from_implementation_and_examples(self) -> None:
        private_path = "/root/" + "newbasebot"
        legacy = "new" + "base-"
        paths = list((ROOT / "src").rglob("*.py")) + list((ROOT / "examples").rglob("*.yaml"))
        for path in paths:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertNotIn(private_path, text)
                self.assertNotIn(legacy, text)
                self.assertNotIn("trading", text.lower())


if __name__ == "__main__":
    unittest.main()
