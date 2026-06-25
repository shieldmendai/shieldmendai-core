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
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shieldmendai.cli import run
from shieldmendai.config import load_config
from shieldmendai.errors import (
    RecoveryTransitionError,
    RecoveryValidationError,
    UnsafeRecoveryError,
)
from shieldmendai.models import RepairActionCategory
from shieldmendai.recovery import (
    BackoffStrategy,
    CircuitBreakerState,
    FailureKind,
    FailureRecord,
    FailureWindow,
    RecoveryController,
    RecoveryControllerState,
    RecoveryOutcome,
    RecoveryTransitionReason,
    RollbackDecision,
    VerificationStatus,
    calculate_backoff,
    evaluate_verification,
    load_recovery_policy,
    load_recovery_scenario,
    load_recovery_state,
    new_recovery_state,
    parse_recovery_policy,
    parse_recovery_scenario,
    parse_recovery_state,
    save_recovery_state,
    transition,
)
from shieldmendai.repair import (
    authorization_context,
    authorize_repair,
    create_repair_plan,
    load_repair_input,
    load_repair_policy,
)

REPAIR = ROOT / "examples" / "repair"
RECOVERY = ROOT / "examples" / "recovery"


def yaml_data(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def plan():
    config = load_config(REPAIR / "config.yaml")
    repair_input = load_repair_input(REPAIR / "request.yaml")
    policy = load_repair_policy(REPAIR / "policy.yaml")
    context = authorization_context(config, repair_input, policy)
    decision = authorize_repair(repair_input.request, context)
    return create_repair_plan(repair_input.request, context, decision)


def cli(*args: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = run(list(args))
    return code, stdout.getvalue(), stderr.getvalue()


class RecoveryPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = yaml_data(RECOVERY / "policy.yaml")

    def test_valid_policy_and_strict_unknown_field(self) -> None:
        self.assertEqual(parse_recovery_policy(self.data).schema_version, "1.0")
        invalid = copy.deepcopy(self.data)
        invalid["policy"]["unexpected"] = True
        with self.assertRaises(RecoveryValidationError):
            parse_recovery_policy(invalid)

    def test_retry_limits_reject_negative_and_excessive_values(self) -> None:
        for value in (-1, 101):
            invalid = copy.deepcopy(self.data)
            invalid["policy"]["retry"]["maximum_repair_attempts"] = value
            with self.subTest(value=value), self.assertRaises(RecoveryValidationError):
                parse_recovery_policy(invalid)

    def test_cooldown_scope_and_values_are_strict(self) -> None:
        cases = (("cooldown_seconds", -1), ("cooldown_scope", "global"), ("bypass_allowed", True))
        for field, value in cases:
            invalid = copy.deepcopy(self.data)
            invalid["policy"]["cooldown"][field] = value
            with self.subTest(field=field), self.assertRaises(RecoveryValidationError):
                parse_recovery_policy(invalid)

    def test_backoff_validation(self) -> None:
        cases = (
            ("strategy", "random"),
            ("multiplier", 0.5),
            ("jitter_enabled", True),
        )
        for field, value in cases:
            invalid = copy.deepcopy(self.data)
            invalid["policy"]["backoff"][field] = value
            with self.subTest(field=field), self.assertRaises(RecoveryValidationError):
                parse_recovery_policy(invalid)
        invalid = copy.deepcopy(self.data)
        invalid["policy"]["backoff"]["initial_delay_seconds"] = 20
        invalid["policy"]["backoff"]["maximum_delay_seconds"] = 10
        with self.assertRaises(RecoveryValidationError):
            parse_recovery_policy(invalid)

    def test_circuit_thresholds_are_finite_and_positive(self) -> None:
        for field in ("failure_threshold", "failure_window_seconds", "open_duration_seconds", "half_open_max_attempts"):
            invalid = copy.deepcopy(self.data)
            invalid["policy"]["circuit_breaker"][field] = 0
            with self.subTest(field=field), self.assertRaises(RecoveryValidationError):
                parse_recovery_policy(invalid)

    def test_backoff_strategies_are_deterministic(self) -> None:
        policy = load_recovery_policy(RECOVERY / "policy.yaml")
        fixed = replace(policy.backoff, strategy=BackoffStrategy.FIXED, initial_delay_seconds=5)
        linear = replace(policy.backoff, strategy=BackoffStrategy.LINEAR, initial_delay_seconds=5)
        exponential = replace(policy.backoff, strategy=BackoffStrategy.EXPONENTIAL, initial_delay_seconds=5, multiplier=2)
        bounded = replace(exponential, strategy=BackoffStrategy.BOUNDED_EXPONENTIAL, maximum_delay_seconds=12)
        self.assertEqual(calculate_backoff(fixed, 3), 5)
        self.assertEqual(calculate_backoff(linear, 3), 15)
        self.assertEqual(calculate_backoff(exponential, 3), 20)
        self.assertEqual(calculate_backoff(bounded, 4), 12)


class LifecycleAndVerificationTests(unittest.TestCase):
    def test_valid_and_invalid_transitions(self) -> None:
        item = transition(
            RecoveryControllerState.IDLE,
            RecoveryControllerState.FINDING_DETECTED,
            RecoveryTransitionReason.RECOVERY_STARTED,
            "2030-01-01T00:00:00Z",
            "started",
        )
        self.assertEqual(item.new_state, RecoveryControllerState.FINDING_DETECTED)
        with self.assertRaises(RecoveryTransitionError):
            transition(
                RecoveryControllerState.IDLE,
                RecoveryControllerState.RESOLVED,
                RecoveryTransitionReason.INCIDENT_RESOLVED,
                "2030-01-01T00:00:00Z",
                "invalid",
            )
        with self.assertRaises(RecoveryTransitionError):
            transition(
                RecoveryControllerState.RESOLVED,
                RecoveryControllerState.FINDING_DETECTED,
                RecoveryTransitionReason.RECOVERY_STARTED,
                "2030-01-01T00:00:00Z",
                "restart",
            )

    def test_verification_pass_failure_inconclusive_and_missing(self) -> None:
        policy = load_recovery_policy(RECOVERY / "policy.yaml")
        passed = evaluate_verification(VerificationStatus.PASSED, 1, policy, evidence_complete=True, adapter_compatible=True)
        failed = evaluate_verification(VerificationStatus.FAILED, 1, policy, evidence_complete=True, adapter_compatible=True)
        inconclusive = evaluate_verification(VerificationStatus.INCONCLUSIVE, 1, policy, evidence_complete=True, adapter_compatible=True)
        missing = evaluate_verification(VerificationStatus.PASSED, 1, policy, evidence_complete=False, adapter_compatible=True)
        self.assertTrue(passed.successful)
        self.assertTrue(failed.retry_allowed)
        self.assertFalse(inconclusive.successful)
        self.assertFalse(missing.successful)

    def test_unknown_verification_and_timestamp_are_rejected(self) -> None:
        scenario = yaml_data(RECOVERY / "scenarios" / "first-success.yaml")
        scenario["verification_outcomes"] = ["unknown"]
        with self.assertRaises(RecoveryValidationError):
            parse_recovery_scenario(scenario)
        scenario = yaml_data(RECOVERY / "scenarios" / "first-success.yaml")
        scenario["now"] = "not-a-time"
        with self.assertRaises(RecoveryValidationError):
            parse_recovery_scenario(scenario)


class ControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_recovery_policy(RECOVERY / "policy.yaml")
        self.plan = plan()

    def simulate(self, name: str, policy=None):
        return RecoveryController(policy or self.policy).simulate(
            self.plan, load_recovery_scenario(RECOVERY / "scenarios" / name)
        )

    def test_first_success_resolves(self) -> None:
        result = self.simulate("first-success.yaml")
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.snapshot.current_state, RecoveryControllerState.RESOLVED)
        self.assertEqual(result.snapshot.final_outcome, RecoveryOutcome.RESOLVED)

    def test_failed_verification_retries_with_distinct_attempt_id(self) -> None:
        result = self.simulate("retry-success.yaml")
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(result.attempts), 2)
        self.assertNotEqual(result.attempts[0].attempt_id, result.attempts[1].attempt_id)
        self.assertIn(RecoveryTransitionReason.BACKOFF_SCHEDULED, {item.reason_code for item in result.transitions})

    def test_retry_exhaustion_and_loop_protection(self) -> None:
        scenario = yaml_data(RECOVERY / "scenarios" / "retry-success.yaml")
        scenario["repair_outcomes"] = ["failure", "failure", "failure", "failure"]
        scenario["verification_outcomes"] = []
        result = RecoveryController(self.policy).simulate(self.plan, parse_recovery_scenario(scenario))
        self.assertIn(result.exit_code, {5, 6})
        reasons = {item.reason_code for item in result.transitions}
        self.assertTrue(
            RecoveryTransitionReason.LOOP_PROTECTION_TRIGGERED in reasons
            or RecoveryTransitionReason.CIRCUIT_OPENED in reasons
        )

    def test_cooldown_blocks_and_exposes_next_time(self) -> None:
        policy = replace(
            self.policy,
            cooldown=replace(self.policy.cooldown, cooldown_seconds=60),
            backoff=replace(self.policy.backoff, initial_delay_seconds=60),
        )
        result = RecoveryController(policy).simulate(
            self.plan, load_recovery_scenario(RECOVERY / "scenarios" / "retry-success.yaml")
        )
        self.assertEqual(result.exit_code, 2)
        self.assertIsNotNone(result.snapshot.next_attempt_at)

    def test_circuit_stays_closed_below_threshold_and_opens_at_threshold(self) -> None:
        below = replace(
            self.policy,
            circuit_breaker=replace(self.policy.circuit_breaker, failure_threshold=3),
        )
        scenario = yaml_data(RECOVERY / "scenarios" / "retry-success.yaml")
        scenario["repair_outcomes"] = ["failure", "success"]
        scenario["verification_outcomes"] = ["passed", "passed"]
        result = RecoveryController(below).simulate(self.plan, parse_recovery_scenario(scenario))
        self.assertEqual(result.snapshot.circuit_state, CircuitBreakerState.CLOSED)
        opening = replace(
            self.policy,
            circuit_breaker=replace(self.policy.circuit_breaker, failure_threshold=1),
        )
        scenario["repair_outcomes"] = ["failure"]
        scenario["verification_outcomes"] = []
        result = RecoveryController(opening).simulate(self.plan, parse_recovery_scenario(scenario))
        self.assertEqual(result.exit_code, 6)
        self.assertEqual(result.snapshot.circuit_state, CircuitBreakerState.OPEN)

    def test_open_circuit_denies_then_half_open_success_closes(self) -> None:
        base = new_recovery_state(self.plan, self.policy, "2030-01-01T00:01:00Z")
        open_state = replace(
            base,
            current_state=RecoveryControllerState.CIRCUIT_OPEN,
            previous_state=RecoveryControllerState.VERIFICATION_FAILED,
            circuit_state=CircuitBreakerState.OPEN,
            circuit_opened_at="2030-01-01T00:00:00Z",
            circuit_reset_at="2030-01-01T00:02:00Z",
        )
        denied = RecoveryController(self.policy).simulate(
            self.plan, load_recovery_scenario(RECOVERY / "scenarios" / "first-success.yaml"), open_state
        )
        self.assertEqual(denied.exit_code, 2)
        half_open = replace(open_state, circuit_reset_at="2030-01-01T00:00:30Z")
        result = RecoveryController(self.policy).simulate(
            self.plan, load_recovery_scenario(RECOVERY / "scenarios" / "first-success.yaml"), half_open
        )
        self.assertEqual(result.snapshot.circuit_state, CircuitBreakerState.CLOSED)

    def test_failed_half_open_reopens_and_is_bounded(self) -> None:
        base = new_recovery_state(self.plan, self.policy, "2030-01-01T00:01:00Z")
        state = replace(
            base,
            current_state=RecoveryControllerState.CIRCUIT_OPEN,
            previous_state=RecoveryControllerState.VERIFICATION_FAILED,
            circuit_state=CircuitBreakerState.OPEN,
            circuit_opened_at="2030-01-01T00:00:00Z",
            circuit_reset_at="2030-01-01T00:00:30Z",
        )
        scenario = yaml_data(RECOVERY / "scenarios" / "first-success.yaml")
        scenario["repair_outcomes"] = ["failure"]
        scenario["verification_outcomes"] = []
        result = RecoveryController(self.policy).simulate(self.plan, parse_recovery_scenario(scenario), state)
        self.assertEqual(result.snapshot.circuit_state, CircuitBreakerState.OPEN)
        bounded = replace(state, half_open_attempts=self.policy.circuit_breaker.half_open_max_attempts)
        result = RecoveryController(self.policy).simulate(
            self.plan, load_recovery_scenario(RECOVERY / "scenarios" / "first-success.yaml"), bounded
        )
        self.assertEqual(result.exit_code, 5)

    def test_duplicate_plan_request_and_attempt_ids_are_rejected(self) -> None:
        state = new_recovery_state(self.plan, self.policy, "2030-01-01T00:01:00Z")
        consumed_plan = replace(state, consumed_plan_ids=(self.plan.plan_id,))
        with self.assertRaises(UnsafeRecoveryError):
            RecoveryController(self.policy).simulate(
                self.plan, load_recovery_scenario(RECOVERY / "scenarios" / "first-success.yaml"), consumed_plan
            )
        key = f"{self.plan.request.request_id}|{self.plan.request.requested_action.value}"
        consumed_request = replace(state, consumed_request_actions=(key,))
        with self.assertRaises(UnsafeRecoveryError):
            RecoveryController(self.policy).simulate(
                self.plan, load_recovery_scenario(RECOVERY / "scenarios" / "first-success.yaml"), consumed_request
            )

    def test_rollback_success_requires_verification_and_failure_exhausts(self) -> None:
        success = self.simulate("rollback-success.yaml")
        self.assertEqual(success.exit_code, 3)
        self.assertEqual(success.snapshot.rollback_status, RollbackDecision.SIMULATED_SUCCESS)
        self.assertEqual(success.snapshot.current_state, RecoveryControllerState.AWAITING_VERIFICATION)
        failure = self.simulate("rollback-failure.yaml")
        self.assertEqual(failure.exit_code, 5)
        self.assertTrue(failure.snapshot.manual_intervention_required)
        self.assertEqual(failure.snapshot.rollback_attempt_count, 2)

    def test_missing_rollback_escalates(self) -> None:
        scenario = yaml_data(RECOVERY / "scenarios" / "rollback-success.yaml")
        scenario["rollback_available"] = False
        result = RecoveryController(self.policy).simulate(self.plan, parse_recovery_scenario(scenario))
        self.assertEqual(result.exit_code, 5)
        self.assertEqual(result.snapshot.current_state, RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED)

    def test_terminal_manual_intervention_cannot_restart(self) -> None:
        state = new_recovery_state(self.plan, self.policy, "2030-01-01T00:01:00Z")
        state = replace(
            state,
            current_state=RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED,
            manual_intervention_required=True,
            final_outcome=RecoveryOutcome.MANUAL_INTERVENTION_REQUIRED,
        )
        with self.assertRaises(RecoveryTransitionError):
            RecoveryController(self.policy).simulate(
                self.plan, load_recovery_scenario(RECOVERY / "scenarios" / "first-success.yaml"), state
            )


class FailureAndSerializationTests(unittest.TestCase):
    def test_failure_window_prunes_and_counts_by_dimensions(self) -> None:
        records = (
            FailureRecord("2030-01-01T00:00:00Z", FailureKind.REPAIR, "target-a", RepairActionCategory.NO_ACTION, "incident-a"),
            FailureRecord("2030-01-01T00:09:00Z", FailureKind.VERIFICATION, "target-a", RepairActionCategory.NO_ACTION, "incident-a"),
            FailureRecord("2030-01-01T00:10:00Z", FailureKind.ROLLBACK, "target-b", RepairActionCategory.NO_ACTION, "incident-b"),
            FailureRecord("2030-01-01T00:10:00Z", FailureKind.AUTHORIZATION, "target-a", RepairActionCategory.NO_ACTION, "incident-a"),
        )
        window = FailureWindow(records).pruned("2030-01-01T00:10:00Z", 120)
        self.assertEqual(len(window.records), 3)
        self.assertEqual(window.count(target_id="target-a", kinds=(FailureKind.VERIFICATION,)), 1)
        self.assertEqual(window.count(kinds=(FailureKind.ROLLBACK,)), 1)
        self.assertEqual(window.count(kinds=(FailureKind.REPAIR,)), 0)

    def test_state_serializes_reloads_and_rejects_invalid_combinations(self) -> None:
        policy = load_recovery_policy(RECOVERY / "policy.yaml")
        result = RecoveryController(policy).simulate(
            plan(), load_recovery_scenario(RECOVERY / "scenarios" / "first-success.yaml")
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            save_recovery_state(result.snapshot, path)
            loaded = load_recovery_state(path)
        self.assertEqual(loaded, result.snapshot)
        data = result.snapshot.to_safe_dict()
        for field, value in (
            ("schema_version", "9.9"),
            ("current_state", "unknown"),
            ("attempt_count", -1),
        ):
            invalid = copy.deepcopy(data)
            invalid[field] = value
            with self.subTest(field=field), self.assertRaises(RecoveryValidationError):
                parse_recovery_state(invalid)
        impossible = copy.deepcopy(data)
        impossible["verification_status"] = "failed"
        with self.assertRaises(RecoveryValidationError):
            parse_recovery_state(impossible)

    def test_secret_like_state_is_rejected(self) -> None:
        policy = load_recovery_policy(RECOVERY / "policy.yaml")
        snapshot = new_recovery_state(plan(), policy, "2030-01-01T00:01:00Z").to_safe_dict()
        snapshot["password"] = "value"
        with self.assertRaises(RecoveryValidationError):
            parse_recovery_state(snapshot)


class CliAndSafetyTests(unittest.TestCase):
    def test_cli_commands_labels_and_exit_codes(self) -> None:
        code, output, _ = cli("inspect-recovery-policy", str(RECOVERY / "policy.yaml"))
        self.assertEqual(code, 0)
        self.assertIn("NO RECOVERY ACTION", output)
        code, output, _ = cli(
            "simulate-recovery",
            str(REPAIR / "config.yaml"),
            str(REPAIR / "request.yaml"),
            str(REPAIR / "policy.yaml"),
            str(RECOVERY / "policy.yaml"),
            str(RECOVERY / "scenarios" / "first-success.yaml"),
        )
        self.assertEqual(code, 0)
        self.assertIn("SIMULATION ONLY — NO LIVE RECOVERY PERFORMED", output)
        self.assertEqual(cli("calculate-backoff", str(RECOVERY / "policy.yaml"), "2")[0], 0)
        self.assertEqual(
            cli(
                "simulate-recovery", str(REPAIR / "config.yaml"), str(REPAIR / "request.yaml"),
                str(REPAIR / "policy.yaml"), str(RECOVERY / "policy.yaml"),
                str(RECOVERY / "scenarios" / "rollback-success.yaml"),
            )[0],
            3,
        )
        self.assertEqual(
            cli(
                "simulate-recovery", str(REPAIR / "config.yaml"), str(REPAIR / "request.yaml"),
                str(REPAIR / "policy.yaml"), str(RECOVERY / "policy.yaml"),
                str(RECOVERY / "scenarios" / "rollback-failure.yaml"),
            )[0],
            5,
        )

    def test_simulation_calls_no_live_boundaries_or_sleep(self) -> None:
        with (
            mock.patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
            mock.patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
            mock.patch.object(os, "system", side_effect=AssertionError("system")),
            mock.patch.object(os, "chmod", side_effect=AssertionError("chmod")),
            mock.patch.object(os, "chown", side_effect=AssertionError("chown")),
            mock.patch.object(time, "sleep", side_effect=AssertionError("sleep")),
            mock.patch.object(socket, "create_connection", side_effect=AssertionError("socket")),
            mock.patch.object(socket.socket, "connect", side_effect=AssertionError("socket")),
            mock.patch("urllib.request.urlopen", side_effect=AssertionError("http")),
        ):
            code, _, _ = cli(
                "simulate-recovery", str(REPAIR / "config.yaml"), str(REPAIR / "request.yaml"),
                str(REPAIR / "policy.yaml"), str(RECOVERY / "policy.yaml"),
                str(RECOVERY / "scenarios" / "first-success.yaml"),
            )
        self.assertEqual(code, 0)

    def test_implementation_has_no_prohibited_execution(self) -> None:
        source = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "src" / "shieldmendai").glob("*.py"))
        for value in (
            "pickle", "time.sleep(", "subprocess.run(", "subprocess.Popen(", "os.system(",
            "socket.connect(", "urlopen(", "systemctl ", "dbus.SystemBus(", "os.chmod(",
            "os.chown(", ".restart(", ".deliver(", "shell=True",
        ):
            with self.subTest(value=value):
                self.assertNotIn(value, source)

    def test_private_legacy_and_domain_specific_names_are_absent(self) -> None:
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
