"""Deterministic, simulation-only recovery verification and loop protection."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar

import yaml

from .errors import RecoveryTransitionError, RecoveryValidationError, UnsafeRecoveryError
from .models import RepairActionCategory, RepairPlan
from .redaction import redact, sanitize_message

SCHEMA_VERSION = "1.0"
MAX_ATTEMPTS = 100
MAX_SECONDS = 31_536_000
_T = TypeVar("_T")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_SECRET_KEY = re.compile(
    r"(token|password|secret|credential|api[_-]?key|private[_-]?key|wallet|seed|"
    r"authorization|cookie|shell|command)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:password|token|api[_-]?key)\s*[:=])",
    re.IGNORECASE,
)
_FORBIDDEN_PRIVATE = "/root/" + "newbasebot"
_FORBIDDEN_PREFIX = "new" + "base-"


class RecoveryControllerState(str, Enum):
    IDLE = "idle"
    FINDING_DETECTED = "finding_detected"
    AUTHORIZATION_REQUIRED = "authorization_required"
    AUTHORIZATION_DENIED = "authorization_denied"
    AUTHORIZED = "authorized"
    WAITING_FOR_COOLDOWN = "waiting_for_cooldown"
    READY_FOR_ATTEMPT = "ready_for_attempt"
    SIMULATED_REPAIR_RUNNING = "simulated_repair_running"
    AWAITING_VERIFICATION = "awaiting_verification"
    VERIFICATION_SUCCEEDED = "verification_succeeded"
    VERIFICATION_FAILED = "verification_failed"
    RETRY_SCHEDULED = "retry_scheduled"
    ROLLBACK_REQUIRED = "rollback_required"
    SIMULATED_ROLLBACK_RUNNING = "simulated_rollback_running"
    ROLLBACK_SUCCEEDED = "rollback_succeeded"
    ROLLBACK_FAILED = "rollback_failed"
    CIRCUIT_OPEN = "circuit_open"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"
    RESOLVED = "resolved"
    ABANDONED = "abandoned"


class RecoveryTransitionReason(str, Enum):
    RECOVERY_STARTED = "recovery_started"
    REPAIR_AUTHORIZED = "repair_authorized"
    REPAIR_DENIED = "repair_denied"
    WAITING_FOR_COOLDOWN = "waiting_for_cooldown"
    BACKOFF_SCHEDULED = "backoff_scheduled"
    RETRY_BUDGET_AVAILABLE = "retry_budget_available"
    RETRY_BUDGET_EXHAUSTED = "retry_budget_exhausted"
    DUPLICATE_ATTEMPT_REJECTED = "duplicate_attempt_rejected"
    PLAN_ALREADY_CONSUMED = "plan_already_consumed"
    INVALID_STATE_TRANSITION = "invalid_state_transition"
    VERIFICATION_PASSED = "verification_passed"
    VERIFICATION_FAILED = "verification_failed"
    VERIFICATION_INCONCLUSIVE = "verification_inconclusive"
    VERIFICATION_ATTEMPTS_EXHAUSTED = "verification_attempts_exhausted"
    ROLLBACK_REQUIRED = "rollback_required"
    ROLLBACK_UNAVAILABLE = "rollback_unavailable"
    ROLLBACK_SUCCEEDED = "rollback_succeeded"
    ROLLBACK_FAILED = "rollback_failed"
    ROLLBACK_ATTEMPTS_EXHAUSTED = "rollback_attempts_exhausted"
    CIRCUIT_OPENED = "circuit_opened"
    CIRCUIT_OPEN = "circuit_open"
    CIRCUIT_HALF_OPEN = "circuit_half_open"
    CIRCUIT_CLOSED = "circuit_closed"
    LOOP_PROTECTION_TRIGGERED = "loop_protection_triggered"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"
    INCIDENT_RESOLVED = "incident_resolved"


class BackoffStrategy(str, Enum):
    FIXED = "fixed"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    BOUNDED_EXPONENTIAL = "bounded_exponential"


class CooldownScope(str, Enum):
    PER_TARGET = "per_target"
    PER_INCIDENT = "per_incident"
    PER_ACTION = "per_action"
    PER_TARGET_ACTION = "per_target_action"


class CircuitBreakerState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class VerificationStatus(str, Enum):
    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"
    UNSUPPORTED = "unsupported"


class RollbackDecision(str, Enum):
    NOT_REQUIRED = "rollback_not_required"
    REQUIRED = "rollback_required"
    NOT_AVAILABLE = "rollback_not_available"
    DENIED = "rollback_denied"
    SCHEDULED = "rollback_scheduled"
    SIMULATED_SUCCESS = "rollback_simulated_success"
    SIMULATED_FAILURE = "rollback_simulated_failure"
    MANUAL_INTERVENTION = "manual_intervention_required"


class RecoveryOutcome(str, Enum):
    PENDING = "pending"
    RESOLVED = "resolved"
    RETRY_POSSIBLE = "retry_possible"
    BLOCKED = "blocked"
    ROLLED_BACK_AWAITING_VERIFICATION = "rolled_back_awaiting_verification"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"
    ABANDONED = "abandoned"


class FailureKind(str, Enum):
    REPAIR = "repair"
    VERIFICATION = "verification"
    ROLLBACK = "rollback"
    AUTHORIZATION = "authorization"


@dataclass(frozen=True)
class RetryPolicy:
    maximum_repair_attempts: int
    maximum_verification_attempts: int
    maximum_rollback_attempts: int
    retryable_outcomes: tuple[str, ...]
    nonretryable_outcomes: tuple[str, ...]
    reset_after_success: bool
    retry_window_seconds: int
    count_attempts_per_target: bool
    count_attempts_per_incident: bool


@dataclass(frozen=True)
class CooldownPolicy:
    cooldown_seconds: int
    cooldown_starts_after: str
    cooldown_scope: CooldownScope
    bypass_allowed: bool = False


@dataclass(frozen=True)
class BackoffPolicy:
    strategy: BackoffStrategy
    initial_delay_seconds: int
    multiplier: float
    maximum_delay_seconds: int
    jitter_enabled: bool = False


@dataclass(frozen=True)
class CircuitBreakerPolicy:
    failure_threshold: int
    failure_window_seconds: int
    open_duration_seconds: int
    half_open_max_attempts: int
    reset_after_success: bool
    count_verification_failures: bool
    count_rollback_failures: bool
    count_authorization_denials: bool


@dataclass(frozen=True)
class VerificationPolicy:
    required: bool
    rollback_on_failure: bool
    manual_intervention_on_inconclusive: bool
    require_complete_evidence: bool
    require_adapter_compatibility: bool


@dataclass(frozen=True)
class RollbackPolicy:
    enabled: bool
    require_known_good_reference: bool
    require_valid_approval: bool
    permitted_risks: tuple[str, ...]


@dataclass(frozen=True)
class RecoveryPolicy:
    schema_version: str
    id: str
    retry: RetryPolicy
    cooldown: CooldownPolicy
    backoff: BackoffPolicy
    circuit_breaker: CircuitBreakerPolicy
    verification: VerificationPolicy
    rollback: RollbackPolicy


@dataclass(frozen=True)
class FailureRecord:
    timestamp: str
    kind: FailureKind
    target_id: str
    action: RepairActionCategory
    incident_id: str


@dataclass(frozen=True)
class FailureWindow:
    records: tuple[FailureRecord, ...] = ()

    def pruned(self, now: str, window_seconds: int) -> "FailureWindow":
        current = _time(now)
        cutoff = current - timedelta(seconds=window_seconds)
        return FailureWindow(
            tuple(
                record
                for record in sorted(self.records, key=lambda item: _time(item.timestamp))
                if cutoff <= _time(record.timestamp) <= current
            )
        )

    def count(
        self,
        *,
        target_id: str | None = None,
        action: RepairActionCategory | None = None,
        incident_id: str | None = None,
        kinds: tuple[FailureKind, ...] | None = None,
    ) -> int:
        return sum(
            1
            for item in self.records
            if (target_id is None or item.target_id == target_id)
            and (action is None or item.action is action)
            and (incident_id is None or item.incident_id == incident_id)
            and (kinds is None or item.kind in kinds)
        )


@dataclass(frozen=True)
class AttemptBudget:
    repair_remaining: int
    verification_remaining: int
    rollback_remaining: int
    exhausted: bool


@dataclass(frozen=True)
class RecoveryTransition:
    prior_state: RecoveryControllerState
    new_state: RecoveryControllerState
    reason_code: RecoveryTransitionReason
    explanation: str
    timestamp: str
    simulation: bool = True


@dataclass(frozen=True)
class RecoveryAttempt:
    attempt_id: str
    idempotency_key: str
    request_id: str
    plan_id: str
    incident_id: str
    target_id: str
    action: RepairActionCategory
    attempt_sequence: int
    consumed: bool
    replayed: bool
    started_at: str
    completed_at: str
    simulation: bool = True


@dataclass(frozen=True)
class VerificationAttempt:
    verification_id: str
    attempt_number: int
    status: VerificationStatus
    observed_status: str
    timestamp: str
    evidence_complete: bool
    adapter_compatible: bool
    simulation: bool = True


@dataclass(frozen=True)
class VerificationEvaluation:
    status: VerificationStatus
    successful: bool
    retry_allowed: bool
    rollback_required: bool
    manual_intervention_required: bool
    reason_code: RecoveryTransitionReason
    explanation: str


@dataclass(frozen=True)
class RecoveryAuditEvent:
    event_id: str
    controller_id: str
    incident_id: str
    request_id: str
    attempt_id: str | None
    target_id: str
    action: RepairActionCategory
    timestamp: str
    prior_state: RecoveryControllerState
    new_state: RecoveryControllerState
    reason_code: RecoveryTransitionReason
    attempt_number: int
    retry_budget_remaining: int
    cooldown_until: str | None
    next_attempt_at: str | None
    circuit_state: CircuitBreakerState
    verification_outcome: VerificationStatus
    rollback_outcome: RollbackDecision
    final_outcome: RecoveryOutcome
    simulation: bool = True

    def to_safe_dict(self) -> dict[str, Any]:
        return redact(_primitive(self))


@dataclass(frozen=True)
class RecoveryStateSnapshot:
    schema_version: str
    controller_id: str
    incident_id: str
    request_id: str
    target_id: str
    action: RepairActionCategory
    policy_reference: str
    current_state: RecoveryControllerState
    previous_state: RecoveryControllerState | None
    attempt_count: int
    verification_attempt_count: int
    rollback_attempt_count: int
    consecutive_failures: int
    failure_window_start: str | None
    last_attempt_at: str | None
    next_attempt_at: str | None
    cooldown_until: str | None
    circuit_state: CircuitBreakerState
    circuit_opened_at: str | None
    circuit_reset_at: str | None
    half_open_attempts: int
    verification_status: VerificationStatus
    rollback_status: RollbackDecision
    final_outcome: RecoveryOutcome
    manual_intervention_required: bool
    consumed_plan_ids: tuple[str, ...]
    consumed_request_actions: tuple[str, ...]
    attempt_ids: tuple[str, ...]
    failure_records: tuple[FailureRecord, ...]
    simulation: bool
    updated_at: str

    def to_safe_dict(self) -> dict[str, Any]:
        return redact(_primitive(self))


@dataclass(frozen=True)
class RecoveryStateRecord:
    snapshot: RecoveryStateSnapshot
    transitions: tuple[RecoveryTransition, ...] = ()
    audit_events: tuple[RecoveryAuditEvent, ...] = ()


@dataclass(frozen=True)
class RecoverySimulationScenario:
    schema_version: str
    scenario_id: str
    now: str
    repair_outcomes: tuple[str, ...]
    verification_outcomes: tuple[VerificationStatus, ...]
    rollback_outcomes: tuple[str, ...]
    evidence_complete: bool
    adapter_compatible: bool
    rollback_available: bool
    known_good_reference_available: bool
    approval_valid: bool
    simulation: bool = True


@dataclass(frozen=True)
class RecoverySimulationResult:
    snapshot: RecoveryStateSnapshot
    transitions: tuple[RecoveryTransition, ...]
    attempts: tuple[RecoveryAttempt, ...]
    verifications: tuple[VerificationAttempt, ...]
    audit_events: tuple[RecoveryAuditEvent, ...]
    exit_code: int
    simulation: bool = True


TERMINAL_STATES = frozenset(
    {
        RecoveryControllerState.AUTHORIZATION_DENIED,
        RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED,
        RecoveryControllerState.RESOLVED,
        RecoveryControllerState.ABANDONED,
    }
)
VALID_TRANSITIONS: dict[RecoveryControllerState, frozenset[RecoveryControllerState]] = {
    RecoveryControllerState.IDLE: frozenset({RecoveryControllerState.FINDING_DETECTED}),
    RecoveryControllerState.FINDING_DETECTED: frozenset({RecoveryControllerState.AUTHORIZATION_REQUIRED}),
    RecoveryControllerState.AUTHORIZATION_REQUIRED: frozenset(
        {RecoveryControllerState.AUTHORIZED, RecoveryControllerState.AUTHORIZATION_DENIED}
    ),
    RecoveryControllerState.AUTHORIZED: frozenset(
        {RecoveryControllerState.WAITING_FOR_COOLDOWN, RecoveryControllerState.READY_FOR_ATTEMPT}
    ),
    RecoveryControllerState.WAITING_FOR_COOLDOWN: frozenset(
        {RecoveryControllerState.READY_FOR_ATTEMPT, RecoveryControllerState.CIRCUIT_OPEN}
    ),
    RecoveryControllerState.READY_FOR_ATTEMPT: frozenset(
        {RecoveryControllerState.SIMULATED_REPAIR_RUNNING, RecoveryControllerState.CIRCUIT_OPEN}
    ),
    RecoveryControllerState.SIMULATED_REPAIR_RUNNING: frozenset(
        {RecoveryControllerState.AWAITING_VERIFICATION, RecoveryControllerState.VERIFICATION_FAILED}
    ),
    RecoveryControllerState.AWAITING_VERIFICATION: frozenset(
        {RecoveryControllerState.VERIFICATION_SUCCEEDED, RecoveryControllerState.VERIFICATION_FAILED}
    ),
    RecoveryControllerState.VERIFICATION_SUCCEEDED: frozenset(
        {RecoveryControllerState.RESOLVED, RecoveryControllerState.CIRCUIT_OPEN}
    ),
    RecoveryControllerState.VERIFICATION_FAILED: frozenset(
        {
            RecoveryControllerState.RETRY_SCHEDULED,
            RecoveryControllerState.ROLLBACK_REQUIRED,
            RecoveryControllerState.CIRCUIT_OPEN,
            RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED,
        }
    ),
    RecoveryControllerState.RETRY_SCHEDULED: frozenset(
        {
            RecoveryControllerState.WAITING_FOR_COOLDOWN,
            RecoveryControllerState.READY_FOR_ATTEMPT,
            RecoveryControllerState.ROLLBACK_REQUIRED,
        }
    ),
    RecoveryControllerState.ROLLBACK_REQUIRED: frozenset(
        {
            RecoveryControllerState.SIMULATED_ROLLBACK_RUNNING,
            RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED,
        }
    ),
    RecoveryControllerState.SIMULATED_ROLLBACK_RUNNING: frozenset(
        {RecoveryControllerState.ROLLBACK_SUCCEEDED, RecoveryControllerState.ROLLBACK_FAILED}
    ),
    RecoveryControllerState.ROLLBACK_SUCCEEDED: frozenset(
        {RecoveryControllerState.AWAITING_VERIFICATION}
    ),
    RecoveryControllerState.ROLLBACK_FAILED: frozenset(
        {
            RecoveryControllerState.RETRY_SCHEDULED,
            RecoveryControllerState.CIRCUIT_OPEN,
            RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED,
        }
    ),
    RecoveryControllerState.CIRCUIT_OPEN: frozenset(
        {
            RecoveryControllerState.READY_FOR_ATTEMPT,
            RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED,
        }
    ),
}


def _primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return {key: _primitive(item) for key, item in asdict(value).items()}
    if isinstance(value, (tuple, list)):
        return [_primitive(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _primitive(item) for key, item in value.items()}
    return value


def _mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryValidationError(f"{location} must be a mapping")
    return value


def _strict(item: dict[str, Any], allowed: set[str], location: str) -> None:
    unknown = sorted(set(item) - allowed)
    if unknown:
        raise RecoveryValidationError(f"{location} contains unknown fields")


def _text(value: Any, location: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RecoveryValidationError(f"{location} must be a non-empty string")
    result = value.strip()
    if _FORBIDDEN_PRIVATE in result or _FORBIDDEN_PREFIX in result:
        raise RecoveryValidationError(f"{location} contains a prohibited private reference")
    if identifier and not _ID.fullmatch(result):
        raise RecoveryValidationError(f"{location} contains unsupported characters")
    if _SECRET_VALUE.search(result):
        raise RecoveryValidationError(f"{location} contains credential-like data")
    return result


def _boolean(value: Any, location: str) -> bool:
    if not isinstance(value, bool):
        raise RecoveryValidationError(f"{location} must be true or false")
    return value


def _integer(value: Any, location: str, maximum: int = MAX_ATTEMPTS) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise RecoveryValidationError(f"{location} must be an integer between 0 and {maximum}")
    return value


def _positive(value: Any, location: str, maximum: int = MAX_ATTEMPTS) -> int:
    result = _integer(value, location, maximum)
    if result < 1:
        raise RecoveryValidationError(f"{location} must be at least 1")
    return result


def _number(value: Any, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise RecoveryValidationError(f"{location} must be a finite number")
    return float(value)


def _enum(enum_type: type[_T], value: Any, location: str) -> _T:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        raise RecoveryValidationError(f"{location} is unknown") from None


def _timestamp(value: Any, location: str, *, now: datetime | None = None) -> str:
    text = _text(value, location)
    parsed = _time(text, location)
    if now is not None and parsed > now + timedelta(days=3660):
        raise RecoveryValidationError(f"{location} is unreasonably far in the future")
    return text


def _time(value: str, location: str = "timestamp") -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise RecoveryValidationError(f"{location} must be an ISO-8601 timestamp") from None
    if parsed.tzinfo is None:
        raise RecoveryValidationError(f"{location} must include a timezone")
    return parsed


def _reject_sensitive(value: Any, location: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _SECRET_KEY.search(str(key)) and item not in (None, "", False):
                raise RecoveryValidationError(f"{location} contains a prohibited sensitive field")
            _reject_sensitive(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_sensitive(item, f"{location}[{index}]")
    elif isinstance(value, str):
        _text(value, location)


def _load(path: str | Path, label: str) -> Any:
    try:
        text = Path(path).read_text(encoding="utf-8")
        return json.loads(text) if str(path).lower().endswith(".json") else yaml.safe_load(text)
    except OSError:
        raise RecoveryValidationError(f"cannot read {label} file") from None
    except (json.JSONDecodeError, yaml.YAMLError):
        raise RecoveryValidationError(f"invalid {label} syntax") from None


def parse_recovery_policy(data: Any) -> RecoveryPolicy:
    root = _mapping(data, "recovery policy")
    _reject_sensitive(root, "recovery policy")
    item = _mapping(root.get("policy", root), "policy")
    _strict(
        item,
        {"schema_version", "id", "retry", "cooldown", "backoff", "circuit_breaker", "verification", "rollback"},
        "policy",
    )
    schema = _text(item.get("schema_version"), "policy.schema_version")
    if schema != SCHEMA_VERSION:
        raise RecoveryValidationError("unsupported recovery policy schema version")
    retry = _mapping(item.get("retry"), "policy.retry")
    _strict(
        retry,
        {
            "maximum_repair_attempts", "maximum_verification_attempts",
            "maximum_rollback_attempts", "retryable_outcomes", "nonretryable_outcomes",
            "reset_after_success", "retry_window_seconds", "count_attempts_per_target",
            "count_attempts_per_incident",
        },
        "policy.retry",
    )
    retryable = tuple(_text(v, "policy.retry.retryable_outcomes", identifier=True) for v in retry.get("retryable_outcomes", []))
    nonretryable = tuple(_text(v, "policy.retry.nonretryable_outcomes", identifier=True) for v in retry.get("nonretryable_outcomes", []))
    if set(retryable) & set(nonretryable):
        raise RecoveryValidationError("retryable and nonretryable outcomes overlap")
    cooldown = _mapping(item.get("cooldown"), "policy.cooldown")
    _strict(cooldown, {"cooldown_seconds", "cooldown_starts_after", "cooldown_scope", "bypass_allowed"}, "policy.cooldown")
    backoff = _mapping(item.get("backoff"), "policy.backoff")
    _strict(backoff, {"strategy", "initial_delay_seconds", "multiplier", "maximum_delay_seconds", "jitter_enabled"}, "policy.backoff")
    initial = _integer(backoff.get("initial_delay_seconds"), "policy.backoff.initial_delay_seconds", MAX_SECONDS)
    maximum = _integer(backoff.get("maximum_delay_seconds"), "policy.backoff.maximum_delay_seconds", MAX_SECONDS)
    multiplier = _number(backoff.get("multiplier"), "policy.backoff.multiplier")
    if multiplier < 1:
        raise RecoveryValidationError("policy.backoff.multiplier must be at least 1")
    if maximum < initial:
        raise RecoveryValidationError("maximum backoff delay cannot be below initial delay")
    if _boolean(backoff.get("jitter_enabled", False), "policy.backoff.jitter_enabled"):
        raise RecoveryValidationError("jitter must remain disabled in Phase 5")
    circuit = _mapping(item.get("circuit_breaker"), "policy.circuit_breaker")
    _strict(
        circuit,
        {
            "failure_threshold", "failure_window_seconds", "open_duration_seconds",
            "half_open_max_attempts", "reset_after_success", "count_verification_failures",
            "count_rollback_failures", "count_authorization_denials",
        },
        "policy.circuit_breaker",
    )
    verification = _mapping(item.get("verification"), "policy.verification")
    _strict(
        verification,
        {"required", "rollback_on_failure", "manual_intervention_on_inconclusive", "require_complete_evidence", "require_adapter_compatibility"},
        "policy.verification",
    )
    rollback = _mapping(item.get("rollback"), "policy.rollback")
    _strict(rollback, {"enabled", "require_known_good_reference", "require_valid_approval", "permitted_risks"}, "policy.rollback")
    bypass = _boolean(cooldown.get("bypass_allowed", False), "policy.cooldown.bypass_allowed")
    if bypass:
        raise RecoveryValidationError("cooldown bypass is unavailable in Phase 5")
    return RecoveryPolicy(
        schema_version=schema,
        id=_text(item.get("id"), "policy.id", identifier=True),
        retry=RetryPolicy(
            _positive(retry.get("maximum_repair_attempts"), "policy.retry.maximum_repair_attempts"),
            _positive(retry.get("maximum_verification_attempts"), "policy.retry.maximum_verification_attempts"),
            _positive(retry.get("maximum_rollback_attempts"), "policy.retry.maximum_rollback_attempts"),
            retryable,
            nonretryable,
            _boolean(retry.get("reset_after_success"), "policy.retry.reset_after_success"),
            _integer(retry.get("retry_window_seconds"), "policy.retry.retry_window_seconds", MAX_SECONDS),
            _boolean(retry.get("count_attempts_per_target"), "policy.retry.count_attempts_per_target"),
            _boolean(retry.get("count_attempts_per_incident"), "policy.retry.count_attempts_per_incident"),
        ),
        cooldown=CooldownPolicy(
            _integer(cooldown.get("cooldown_seconds"), "policy.cooldown.cooldown_seconds", MAX_SECONDS),
            _text(cooldown.get("cooldown_starts_after"), "policy.cooldown.cooldown_starts_after", identifier=True),
            _enum(CooldownScope, cooldown.get("cooldown_scope"), "policy.cooldown.cooldown_scope"),
            False,
        ),
        backoff=BackoffPolicy(
            _enum(BackoffStrategy, backoff.get("strategy"), "policy.backoff.strategy"),
            initial,
            multiplier,
            maximum,
            False,
        ),
        circuit_breaker=CircuitBreakerPolicy(
            _positive(circuit.get("failure_threshold"), "policy.circuit_breaker.failure_threshold"),
            _positive(circuit.get("failure_window_seconds"), "policy.circuit_breaker.failure_window_seconds", MAX_SECONDS),
            _positive(circuit.get("open_duration_seconds"), "policy.circuit_breaker.open_duration_seconds", MAX_SECONDS),
            _positive(circuit.get("half_open_max_attempts"), "policy.circuit_breaker.half_open_max_attempts"),
            _boolean(circuit.get("reset_after_success"), "policy.circuit_breaker.reset_after_success"),
            _boolean(circuit.get("count_verification_failures"), "policy.circuit_breaker.count_verification_failures"),
            _boolean(circuit.get("count_rollback_failures"), "policy.circuit_breaker.count_rollback_failures"),
            _boolean(circuit.get("count_authorization_denials"), "policy.circuit_breaker.count_authorization_denials"),
        ),
        verification=VerificationPolicy(
            _boolean(verification.get("required"), "policy.verification.required"),
            _boolean(verification.get("rollback_on_failure"), "policy.verification.rollback_on_failure"),
            _boolean(verification.get("manual_intervention_on_inconclusive"), "policy.verification.manual_intervention_on_inconclusive"),
            _boolean(verification.get("require_complete_evidence"), "policy.verification.require_complete_evidence"),
            _boolean(verification.get("require_adapter_compatibility"), "policy.verification.require_adapter_compatibility"),
        ),
        rollback=RollbackPolicy(
            _boolean(rollback.get("enabled"), "policy.rollback.enabled"),
            _boolean(rollback.get("require_known_good_reference"), "policy.rollback.require_known_good_reference"),
            _boolean(rollback.get("require_valid_approval"), "policy.rollback.require_valid_approval"),
            tuple(_text(v, "policy.rollback.permitted_risks", identifier=True) for v in rollback.get("permitted_risks", [])),
        ),
    )


def load_recovery_policy(path: str | Path) -> RecoveryPolicy:
    return parse_recovery_policy(_load(path, "recovery policy"))


def calculate_backoff(policy: BackoffPolicy, attempt_number: int) -> int:
    if isinstance(attempt_number, bool) or not isinstance(attempt_number, int) or not 1 <= attempt_number <= MAX_ATTEMPTS:
        raise RecoveryValidationError(f"attempt number must be between 1 and {MAX_ATTEMPTS}")
    if policy.strategy is BackoffStrategy.FIXED:
        delay = policy.initial_delay_seconds
    elif policy.strategy is BackoffStrategy.LINEAR:
        delay = policy.initial_delay_seconds * attempt_number
    elif policy.strategy in {BackoffStrategy.EXPONENTIAL, BackoffStrategy.BOUNDED_EXPONENTIAL}:
        try:
            delay = policy.initial_delay_seconds * policy.multiplier ** (attempt_number - 1)
        except OverflowError:
            delay = policy.maximum_delay_seconds
    else:
        raise RecoveryValidationError("unknown backoff strategy")
    if not math.isfinite(delay):
        delay = policy.maximum_delay_seconds
    return int(min(delay, policy.maximum_delay_seconds))


def next_eligible_at(policy: RecoveryPolicy, last_attempt_at: str, attempt_number: int) -> str:
    start = _time(last_attempt_at)
    delay = max(policy.cooldown.cooldown_seconds, calculate_backoff(policy.backoff, attempt_number))
    try:
        return (start + timedelta(seconds=delay)).isoformat().replace("+00:00", "Z")
    except OverflowError:
        raise RecoveryValidationError("backoff would overflow timestamp") from None


def transition(
    state: RecoveryControllerState,
    new_state: RecoveryControllerState,
    reason: RecoveryTransitionReason,
    timestamp: str,
    explanation: str,
) -> RecoveryTransition:
    if state in TERMINAL_STATES or new_state not in VALID_TRANSITIONS.get(state, frozenset()):
        raise RecoveryTransitionError("invalid recovery state transition")
    return RecoveryTransition(
        state,
        new_state,
        reason,
        sanitize_message(explanation),
        _timestamp(timestamp, "transition.timestamp"),
        True,
    )


def evaluate_verification(
    status: VerificationStatus,
    attempt_number: int,
    policy: RecoveryPolicy,
    *,
    evidence_complete: bool,
    adapter_compatible: bool,
) -> VerificationEvaluation:
    if attempt_number < 1 or attempt_number > policy.retry.maximum_verification_attempts:
        raise RecoveryValidationError("verification attempt number exceeds policy")
    if policy.verification.require_complete_evidence and not evidence_complete:
        return VerificationEvaluation(
            VerificationStatus.FAILED, False, False, policy.verification.rollback_on_failure,
            not policy.verification.rollback_on_failure,
            RecoveryTransitionReason.VERIFICATION_FAILED,
            "Required verification evidence is incomplete.",
        )
    if policy.verification.require_adapter_compatibility and not adapter_compatible:
        return VerificationEvaluation(
            VerificationStatus.FAILED, False, False, policy.verification.rollback_on_failure,
            not policy.verification.rollback_on_failure,
            RecoveryTransitionReason.VERIFICATION_FAILED,
            "Verification adapter is incompatible.",
        )
    if status is VerificationStatus.PASSED:
        return VerificationEvaluation(
            status, True, False, False, False,
            RecoveryTransitionReason.VERIFICATION_PASSED, "Deterministic verification passed."
        )
    exhausted = attempt_number >= policy.retry.maximum_verification_attempts
    inconclusive = status is VerificationStatus.INCONCLUSIVE
    return VerificationEvaluation(
        status,
        False,
        not exhausted and status is VerificationStatus.FAILED,
        exhausted and policy.verification.rollback_on_failure,
        inconclusive and policy.verification.manual_intervention_on_inconclusive
        or exhausted and not policy.verification.rollback_on_failure,
        RecoveryTransitionReason.VERIFICATION_INCONCLUSIVE if inconclusive
        else RecoveryTransitionReason.VERIFICATION_ATTEMPTS_EXHAUSTED if exhausted
        else RecoveryTransitionReason.VERIFICATION_FAILED,
        "Verification did not establish success.",
    )


def rollback_decision(
    plan: RepairPlan,
    policy: RecoveryPolicy,
    snapshot: RecoveryStateSnapshot,
    *,
    rollback_available: bool,
    known_good_reference_available: bool,
    approval_valid: bool,
) -> RollbackDecision:
    if snapshot.verification_status is VerificationStatus.PASSED:
        return RollbackDecision.NOT_REQUIRED
    if not policy.rollback.enabled or not rollback_available or plan.rollback_plan is None:
        return RollbackDecision.NOT_AVAILABLE
    if policy.rollback.require_known_good_reference and not known_good_reference_available:
        return RollbackDecision.NOT_AVAILABLE
    if policy.rollback.require_valid_approval and not approval_valid:
        return RollbackDecision.DENIED
    if snapshot.rollback_attempt_count >= policy.retry.maximum_rollback_attempts:
        return RollbackDecision.MANUAL_INTERVENTION
    return RollbackDecision.REQUIRED


def _parse_failure(raw: Any, location: str) -> FailureRecord:
    item = _mapping(raw, location)
    return FailureRecord(
        _timestamp(item.get("timestamp"), f"{location}.timestamp"),
        _enum(FailureKind, item.get("kind"), f"{location}.kind"),
        _text(item.get("target_id"), f"{location}.target_id", identifier=True),
        _enum(RepairActionCategory, item.get("action"), f"{location}.action"),
        _text(item.get("incident_id"), f"{location}.incident_id", identifier=True),
    )


def parse_recovery_scenario(data: Any) -> RecoverySimulationScenario:
    root = _mapping(data, "recovery scenario")
    _reject_sensitive(root, "recovery scenario")
    _strict(
        root,
        {
            "schema_version", "scenario_id", "now", "repair_outcomes",
            "verification_outcomes", "rollback_outcomes", "evidence_complete",
            "adapter_compatible", "rollback_available",
            "known_good_reference_available", "approval_valid", "simulation",
        },
        "recovery scenario",
    )
    schema = _text(root.get("schema_version"), "scenario.schema_version")
    if schema != SCHEMA_VERSION:
        raise RecoveryValidationError("unsupported recovery scenario schema version")
    simulation = _boolean(root.get("simulation"), "scenario.simulation")
    if not simulation:
        raise UnsafeRecoveryError("simulation mode is required")
    repairs = tuple(_text(v, "scenario.repair_outcomes", identifier=True) for v in root.get("repair_outcomes", []))
    rollbacks = tuple(_text(v, "scenario.rollback_outcomes", identifier=True) for v in root.get("rollback_outcomes", []))
    if not repairs or any(v not in {"success", "failure"} for v in repairs):
        raise RecoveryValidationError("scenario repair outcomes are invalid")
    if any(v not in {"success", "failure"} for v in rollbacks):
        raise RecoveryValidationError("scenario rollback outcomes are invalid")
    return RecoverySimulationScenario(
        schema,
        _text(root.get("scenario_id"), "scenario.scenario_id", identifier=True),
        _timestamp(root.get("now"), "scenario.now"),
        repairs,
        tuple(_enum(VerificationStatus, v, "scenario.verification_outcomes") for v in root.get("verification_outcomes", [])),
        rollbacks,
        _boolean(root.get("evidence_complete"), "scenario.evidence_complete"),
        _boolean(root.get("adapter_compatible"), "scenario.adapter_compatible"),
        _boolean(root.get("rollback_available"), "scenario.rollback_available"),
        _boolean(root.get("known_good_reference_available"), "scenario.known_good_reference_available"),
        _boolean(root.get("approval_valid"), "scenario.approval_valid"),
        True,
    )


def load_recovery_scenario(path: str | Path) -> RecoverySimulationScenario:
    return parse_recovery_scenario(_load(path, "recovery scenario"))


def new_recovery_state(plan: RepairPlan, policy: RecoveryPolicy, now: str) -> RecoveryStateSnapshot:
    if not plan.simulation or plan.production_execution_available:
        raise UnsafeRecoveryError("only simulation repair plans are accepted")
    return RecoveryStateSnapshot(
        SCHEMA_VERSION,
        f"controller-{plan.request.incident_id}",
        plan.request.incident_id,
        plan.request.request_id,
        plan.request.target_id,
        plan.request.requested_action,
        policy.id,
        RecoveryControllerState.IDLE,
        None,
        0, 0, 0, 0,
        None, None, None, None,
        CircuitBreakerState.CLOSED,
        None, None, 0,
        VerificationStatus.PENDING,
        RollbackDecision.NOT_REQUIRED,
        RecoveryOutcome.PENDING,
        False,
        (), (), (), (),
        True,
        _timestamp(now, "state.updated_at"),
    )


def _replace(snapshot: RecoveryStateSnapshot, **changes: Any) -> RecoveryStateSnapshot:
    values = {**snapshot.__dict__, **changes}
    return RecoveryStateSnapshot(**values)


def _attempt_id(plan: RepairPlan, sequence: int) -> str:
    value = f"{plan.plan_id}|{plan.request.request_id}|{plan.request.requested_action.value}|{sequence}"
    return f"attempt-{hashlib.sha256(value.encode()).hexdigest()[:16]}"


def _event(snapshot: RecoveryStateSnapshot, item: RecoveryTransition, attempt_id: str | None, policy: RecoveryPolicy) -> RecoveryAuditEvent:
    return RecoveryAuditEvent(
        f"event-{snapshot.controller_id}-{len(snapshot.attempt_ids)}-{item.new_state.value}",
        snapshot.controller_id, snapshot.incident_id, snapshot.request_id, attempt_id,
        snapshot.target_id, snapshot.action, item.timestamp, item.prior_state, item.new_state,
        item.reason_code, snapshot.attempt_count,
        max(0, policy.retry.maximum_repair_attempts - snapshot.attempt_count),
        snapshot.cooldown_until, snapshot.next_attempt_at, snapshot.circuit_state,
        snapshot.verification_status, snapshot.rollback_status, snapshot.final_outcome, True,
    )


class RecoveryController:
    """Runs one bounded deterministic scenario without recursion or live access."""

    def __init__(self, policy: RecoveryPolicy) -> None:
        self.policy = policy

    def simulate(
        self,
        plan: RepairPlan,
        scenario: RecoverySimulationScenario,
        state: RecoveryStateSnapshot | None = None,
    ) -> RecoverySimulationResult:
        if not scenario.simulation or not plan.simulation or plan.production_execution_available:
            raise UnsafeRecoveryError("production recovery is unavailable")
        if plan.request.requested_action is RepairActionCategory.APPLY_APPROVED_CODE_PATCH:
            raise UnsafeRecoveryError("code-patch execution remains prohibited")
        fresh = state is None
        snapshot = state or new_recovery_state(plan, self.policy, scenario.now)
        if snapshot.current_state in TERMINAL_STATES:
            raise RecoveryTransitionError("terminal recovery state cannot restart")
        request_action = f"{plan.request.request_id}|{plan.request.requested_action.value}"
        if plan.plan_id in snapshot.consumed_plan_ids:
            raise UnsafeRecoveryError(RecoveryTransitionReason.PLAN_ALREADY_CONSUMED.value)
        if request_action in snapshot.consumed_request_actions:
            raise UnsafeRecoveryError(RecoveryTransitionReason.DUPLICATE_ATTEMPT_REJECTED.value)

        transitions: list[RecoveryTransition] = []
        attempts: list[RecoveryAttempt] = []
        verifications: list[VerificationAttempt] = []
        audits: list[RecoveryAuditEvent] = []

        def move(new: RecoveryControllerState, reason: RecoveryTransitionReason, explanation: str) -> None:
            nonlocal snapshot
            item = transition(snapshot.current_state, new, reason, scenario.now, explanation)
            transitions.append(item)
            snapshot = _replace(snapshot, previous_state=item.prior_state, current_state=item.new_state, updated_at=scenario.now)
            audits.append(_event(snapshot, item, attempts[-1].attempt_id if attempts else None, self.policy))

        if fresh:
            move(RecoveryControllerState.FINDING_DETECTED, RecoveryTransitionReason.RECOVERY_STARTED, "Fictional finding entered recovery.")
            move(RecoveryControllerState.AUTHORIZATION_REQUIRED, RecoveryTransitionReason.RECOVERY_STARTED, "Explicit Phase 4 authorization is required.")
            if not plan.authorization.permitted:
                move(RecoveryControllerState.AUTHORIZATION_DENIED, RecoveryTransitionReason.REPAIR_DENIED, "Repair authorization denied.")
                return RecoverySimulationResult(snapshot, tuple(transitions), (), (), tuple(audits), 2)
            move(RecoveryControllerState.AUTHORIZED, RecoveryTransitionReason.REPAIR_AUTHORIZED, "Simulation repair plan is authorized.")

        current_time = _time(scenario.now)
        if snapshot.circuit_state is CircuitBreakerState.OPEN:
            if snapshot.circuit_reset_at is None or current_time < _time(snapshot.circuit_reset_at):
                return RecoverySimulationResult(_replace(snapshot, final_outcome=RecoveryOutcome.BLOCKED), tuple(transitions), (), (), tuple(audits), 2)
            if snapshot.half_open_attempts >= self.policy.circuit_breaker.half_open_max_attempts:
                move(RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED, RecoveryTransitionReason.LOOP_PROTECTION_TRIGGERED, "Half-open attempt budget is exhausted.")
                snapshot = _replace(
                    snapshot,
                    manual_intervention_required=True,
                    final_outcome=RecoveryOutcome.MANUAL_INTERVENTION_REQUIRED,
                )
                return RecoverySimulationResult(snapshot, tuple(transitions), (), (), tuple(audits), 5)
            snapshot = _replace(snapshot, circuit_state=CircuitBreakerState.HALF_OPEN)

        for index, repair_outcome in enumerate(scenario.repair_outcomes, start=1):
            if index > self.policy.retry.maximum_repair_attempts:
                if snapshot.current_state is RecoveryControllerState.VERIFICATION_FAILED:
                    move(RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED, RecoveryTransitionReason.LOOP_PROTECTION_TRIGGERED, "Repair attempt budget is exhausted.")
                snapshot = _replace(snapshot, manual_intervention_required=True, final_outcome=RecoveryOutcome.MANUAL_INTERVENTION_REQUIRED)
                return RecoverySimulationResult(snapshot, tuple(transitions), tuple(attempts), tuple(verifications), tuple(audits), 5)
            if snapshot.last_attempt_at:
                eligible = next_eligible_at(self.policy, snapshot.last_attempt_at, index)
                if current_time < _time(eligible):
                    if snapshot.current_state is RecoveryControllerState.AUTHORIZED:
                        move(RecoveryControllerState.WAITING_FOR_COOLDOWN, RecoveryTransitionReason.WAITING_FOR_COOLDOWN, "Cooldown or backoff has not elapsed.")
                    snapshot = _replace(snapshot, cooldown_until=eligible, next_attempt_at=eligible, final_outcome=RecoveryOutcome.BLOCKED)
                    return RecoverySimulationResult(snapshot, tuple(transitions), tuple(attempts), tuple(verifications), tuple(audits), 2)
            if snapshot.current_state in {RecoveryControllerState.AUTHORIZED, RecoveryControllerState.RETRY_SCHEDULED, RecoveryControllerState.CIRCUIT_OPEN}:
                if snapshot.current_state is RecoveryControllerState.RETRY_SCHEDULED and self.policy.cooldown.cooldown_seconds:
                    move(RecoveryControllerState.WAITING_FOR_COOLDOWN, RecoveryTransitionReason.WAITING_FOR_COOLDOWN, "Deterministic cooldown evaluated.")
                if snapshot.current_state is RecoveryControllerState.WAITING_FOR_COOLDOWN:
                    snapshot = _replace(snapshot, next_attempt_at=None, cooldown_until=None)
                move(RecoveryControllerState.READY_FOR_ATTEMPT, RecoveryTransitionReason.RETRY_BUDGET_AVAILABLE, "Bounded attempt budget remains.")
            move(RecoveryControllerState.SIMULATED_REPAIR_RUNNING, RecoveryTransitionReason.REPAIR_AUTHORIZED, "Simulated repair outcome is scenario supplied.")
            attempt_id = _attempt_id(plan, snapshot.attempt_count + 1)
            if attempt_id in snapshot.attempt_ids:
                raise UnsafeRecoveryError(RecoveryTransitionReason.DUPLICATE_ATTEMPT_REJECTED.value)
            attempts.append(
                RecoveryAttempt(
                    attempt_id, f"{plan.plan_id}:{snapshot.attempt_count + 1}",
                    plan.request.request_id, plan.plan_id, plan.request.incident_id,
                    plan.request.target_id, plan.request.requested_action,
                    snapshot.attempt_count + 1, True, False, scenario.now, scenario.now, True,
                )
            )
            snapshot = _replace(
                snapshot,
                attempt_count=snapshot.attempt_count + 1,
                last_attempt_at=scenario.now,
                attempt_ids=(*snapshot.attempt_ids, attempt_id),
                consumed_plan_ids=(*snapshot.consumed_plan_ids, plan.plan_id) if index == 1 else snapshot.consumed_plan_ids,
                consumed_request_actions=(*snapshot.consumed_request_actions, request_action) if index == 1 else snapshot.consumed_request_actions,
                half_open_attempts=snapshot.half_open_attempts + (1 if snapshot.circuit_state is CircuitBreakerState.HALF_OPEN else 0),
            )
            if repair_outcome == "failure":
                move(RecoveryControllerState.VERIFICATION_FAILED, RecoveryTransitionReason.VERIFICATION_FAILED, "Simulated repair outcome failed.")
                evaluation = VerificationEvaluation(VerificationStatus.FAILED, False, index < self.policy.retry.maximum_repair_attempts, False, False, RecoveryTransitionReason.VERIFICATION_FAILED, "Repair simulation failed.")
            else:
                move(RecoveryControllerState.AWAITING_VERIFICATION, RecoveryTransitionReason.REPAIR_AUTHORIZED, "Deterministic verification is required.")
                if index > len(scenario.verification_outcomes):
                    evaluation = VerificationEvaluation(VerificationStatus.FAILED, False, False, self.policy.verification.rollback_on_failure, not self.policy.verification.rollback_on_failure, RecoveryTransitionReason.VERIFICATION_FAILED, "Required verification outcome is missing.")
                else:
                    status = scenario.verification_outcomes[index - 1]
                    evaluation = evaluate_verification(status, min(index, self.policy.retry.maximum_verification_attempts), self.policy, evidence_complete=scenario.evidence_complete, adapter_compatible=scenario.adapter_compatible)
                    verifications.append(VerificationAttempt(f"verification-{attempt_id}", index, status, status.value, scenario.now, scenario.evidence_complete, scenario.adapter_compatible, True))
                snapshot = _replace(snapshot, verification_attempt_count=snapshot.verification_attempt_count + 1, verification_status=evaluation.status)
                if evaluation.successful:
                    move(RecoveryControllerState.VERIFICATION_SUCCEEDED, RecoveryTransitionReason.VERIFICATION_PASSED, evaluation.explanation)
                    if snapshot.circuit_state is CircuitBreakerState.HALF_OPEN:
                        snapshot = _replace(snapshot, circuit_state=CircuitBreakerState.CLOSED, circuit_opened_at=None, circuit_reset_at=None, half_open_attempts=0, consecutive_failures=0)
                    move(RecoveryControllerState.RESOLVED, RecoveryTransitionReason.INCIDENT_RESOLVED, "Incident resolved by deterministic verification.")
                    snapshot = _replace(snapshot, final_outcome=RecoveryOutcome.RESOLVED)
                    return RecoverySimulationResult(snapshot, tuple(transitions), tuple(attempts), tuple(verifications), tuple(audits), 0)
                move(RecoveryControllerState.VERIFICATION_FAILED, evaluation.reason_code, evaluation.explanation)

            kind = FailureKind.REPAIR if repair_outcome == "failure" else FailureKind.VERIFICATION
            records = (*snapshot.failure_records, FailureRecord(scenario.now, kind, snapshot.target_id, snapshot.action, snapshot.incident_id))
            window = FailureWindow(records).pruned(scenario.now, self.policy.circuit_breaker.failure_window_seconds)
            counted_kinds = [FailureKind.REPAIR]
            if self.policy.circuit_breaker.count_verification_failures:
                counted_kinds.append(FailureKind.VERIFICATION)
            failures = window.count(target_id=snapshot.target_id, action=snapshot.action, kinds=tuple(counted_kinds))
            snapshot = _replace(snapshot, failure_records=window.records, consecutive_failures=snapshot.consecutive_failures + 1, failure_window_start=window.records[0].timestamp if window.records else None)
            if snapshot.circuit_state is CircuitBreakerState.HALF_OPEN or failures >= self.policy.circuit_breaker.failure_threshold:
                move(RecoveryControllerState.CIRCUIT_OPEN, RecoveryTransitionReason.CIRCUIT_OPENED, "Failure threshold opened the deterministic circuit.")
                reset = (current_time + timedelta(seconds=self.policy.circuit_breaker.open_duration_seconds)).isoformat().replace("+00:00", "Z")
                snapshot = _replace(snapshot, circuit_state=CircuitBreakerState.OPEN, circuit_opened_at=scenario.now, circuit_reset_at=reset, final_outcome=RecoveryOutcome.BLOCKED)
                return RecoverySimulationResult(snapshot, tuple(transitions), tuple(attempts), tuple(verifications), tuple(audits), 6)
            if evaluation.retry_allowed and index < len(scenario.repair_outcomes):
                move(RecoveryControllerState.RETRY_SCHEDULED, RecoveryTransitionReason.BACKOFF_SCHEDULED, "Retry scheduled with deterministic cooldown and backoff.")
                snapshot = _replace(snapshot, next_attempt_at=next_eligible_at(self.policy, scenario.now, index + 1), final_outcome=RecoveryOutcome.RETRY_POSSIBLE)
                continue

            decision = rollback_decision(
                plan, self.policy, snapshot,
                rollback_available=scenario.rollback_available,
                known_good_reference_available=scenario.known_good_reference_available,
                approval_valid=scenario.approval_valid,
            )
            snapshot = _replace(snapshot, rollback_status=decision)
            if decision in {RollbackDecision.NOT_AVAILABLE, RollbackDecision.DENIED, RollbackDecision.MANUAL_INTERVENTION}:
                move(RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED, RecoveryTransitionReason.ROLLBACK_UNAVAILABLE, "Required rollback is unavailable or denied.")
                snapshot = _replace(snapshot, manual_intervention_required=True, final_outcome=RecoveryOutcome.MANUAL_INTERVENTION_REQUIRED)
                return RecoverySimulationResult(snapshot, tuple(transitions), tuple(attempts), tuple(verifications), tuple(audits), 5)
            if decision is RollbackDecision.REQUIRED:
                move(RecoveryControllerState.ROLLBACK_REQUIRED, RecoveryTransitionReason.ROLLBACK_REQUIRED, "Verification failure requires modeled rollback.")
                for rollback_index in range(self.policy.retry.maximum_rollback_attempts):
                    move(RecoveryControllerState.SIMULATED_ROLLBACK_RUNNING, RecoveryTransitionReason.ROLLBACK_REQUIRED, "Rollback outcome is scenario supplied.")
                    outcome = scenario.rollback_outcomes[rollback_index] if rollback_index < len(scenario.rollback_outcomes) else "failure"
                    snapshot = _replace(snapshot, rollback_attempt_count=snapshot.rollback_attempt_count + 1)
                    if outcome == "success":
                        move(RecoveryControllerState.ROLLBACK_SUCCEEDED, RecoveryTransitionReason.ROLLBACK_SUCCEEDED, "Simulated rollback succeeded; verification remains required.")
                        snapshot = _replace(snapshot, rollback_status=RollbackDecision.SIMULATED_SUCCESS, final_outcome=RecoveryOutcome.ROLLED_BACK_AWAITING_VERIFICATION)
                        move(RecoveryControllerState.AWAITING_VERIFICATION, RecoveryTransitionReason.ROLLBACK_SUCCEEDED, "Post-rollback verification is required.")
                        return RecoverySimulationResult(snapshot, tuple(transitions), tuple(attempts), tuple(verifications), tuple(audits), 3)
                    move(RecoveryControllerState.ROLLBACK_FAILED, RecoveryTransitionReason.ROLLBACK_FAILED, "Simulated rollback failed.")
                    if rollback_index + 1 < self.policy.retry.maximum_rollback_attempts:
                        move(RecoveryControllerState.RETRY_SCHEDULED, RecoveryTransitionReason.BACKOFF_SCHEDULED, "Bounded rollback retry scheduled.")
                        move(RecoveryControllerState.ROLLBACK_REQUIRED, RecoveryTransitionReason.ROLLBACK_REQUIRED, "Rollback retry budget remains.")
                        continue
                    move(RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED, RecoveryTransitionReason.ROLLBACK_ATTEMPTS_EXHAUSTED, "Rollback attempt budget is exhausted.")
                    snapshot = _replace(snapshot, rollback_status=RollbackDecision.SIMULATED_FAILURE, manual_intervention_required=True, final_outcome=RecoveryOutcome.MANUAL_INTERVENTION_REQUIRED)
                    return RecoverySimulationResult(snapshot, tuple(transitions), tuple(attempts), tuple(verifications), tuple(audits), 5)

        if snapshot.current_state is RecoveryControllerState.VERIFICATION_FAILED:
            move(RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED, RecoveryTransitionReason.LOOP_PROTECTION_TRIGGERED, "Recovery scenario ended without safe resolution.")
        snapshot = _replace(snapshot, manual_intervention_required=True, final_outcome=RecoveryOutcome.MANUAL_INTERVENTION_REQUIRED)
        return RecoverySimulationResult(snapshot, tuple(transitions), tuple(attempts), tuple(verifications), tuple(audits), 5)


def serialize_recovery_state(snapshot: RecoveryStateSnapshot) -> dict[str, Any]:
    validate_recovery_state(snapshot)
    return snapshot.to_safe_dict()


def save_recovery_state(snapshot: RecoveryStateSnapshot, path: str | Path) -> None:
    target = Path(path)
    target.write_text(json.dumps(serialize_recovery_state(snapshot), indent=2, sort_keys=True), encoding="utf-8")


def parse_recovery_state(data: Any) -> RecoveryStateSnapshot:
    root = _mapping(data, "recovery state")
    _reject_sensitive(root, "recovery state")
    required = set(RecoveryStateSnapshot.__dataclass_fields__)
    if set(root) != required:
        raise RecoveryValidationError("recovery state fields do not match the versioned schema")
    if root.get("schema_version") != SCHEMA_VERSION:
        raise RecoveryValidationError("unsupported recovery state schema version")
    failures = tuple(_parse_failure(item, f"failure_records[{index}]") for index, item in enumerate(root["failure_records"]))
    snapshot = RecoveryStateSnapshot(
        SCHEMA_VERSION,
        _text(root["controller_id"], "controller_id", identifier=True),
        _text(root["incident_id"], "incident_id", identifier=True),
        _text(root["request_id"], "request_id", identifier=True),
        _text(root["target_id"], "target_id", identifier=True),
        _enum(RepairActionCategory, root["action"], "action"),
        _text(root["policy_reference"], "policy_reference", identifier=True),
        _enum(RecoveryControllerState, root["current_state"], "current_state"),
        _enum(RecoveryControllerState, root["previous_state"], "previous_state") if root["previous_state"] is not None else None,
        _integer(root["attempt_count"], "attempt_count"),
        _integer(root["verification_attempt_count"], "verification_attempt_count"),
        _integer(root["rollback_attempt_count"], "rollback_attempt_count"),
        _integer(root["consecutive_failures"], "consecutive_failures"),
        _timestamp(root["failure_window_start"], "failure_window_start") if root["failure_window_start"] else None,
        _timestamp(root["last_attempt_at"], "last_attempt_at") if root["last_attempt_at"] else None,
        _timestamp(root["next_attempt_at"], "next_attempt_at") if root["next_attempt_at"] else None,
        _timestamp(root["cooldown_until"], "cooldown_until") if root["cooldown_until"] else None,
        _enum(CircuitBreakerState, root["circuit_state"], "circuit_state"),
        _timestamp(root["circuit_opened_at"], "circuit_opened_at") if root["circuit_opened_at"] else None,
        _timestamp(root["circuit_reset_at"], "circuit_reset_at") if root["circuit_reset_at"] else None,
        _integer(root["half_open_attempts"], "half_open_attempts"),
        _enum(VerificationStatus, root["verification_status"], "verification_status"),
        _enum(RollbackDecision, root["rollback_status"], "rollback_status"),
        _enum(RecoveryOutcome, root["final_outcome"], "final_outcome"),
        _boolean(root["manual_intervention_required"], "manual_intervention_required"),
        tuple(_text(v, "consumed_plan_ids", identifier=True) for v in root["consumed_plan_ids"]),
        tuple(_text(v, "consumed_request_actions") for v in root["consumed_request_actions"]),
        tuple(_text(v, "attempt_ids", identifier=True) for v in root["attempt_ids"]),
        failures,
        _boolean(root["simulation"], "simulation"),
        _timestamp(root["updated_at"], "updated_at"),
    )
    validate_recovery_state(snapshot)
    return snapshot


def load_recovery_state(path: str | Path) -> RecoveryStateSnapshot:
    return parse_recovery_state(_load(path, "recovery state"))


def validate_recovery_state(snapshot: RecoveryStateSnapshot) -> None:
    if snapshot.schema_version != SCHEMA_VERSION or not snapshot.simulation:
        raise RecoveryValidationError("recovery state must use schema 1.0 and simulation mode")
    if len(set(snapshot.attempt_ids)) != len(snapshot.attempt_ids):
        raise RecoveryValidationError("duplicate attempt identifiers are prohibited")
    if len(set(snapshot.consumed_plan_ids)) != len(snapshot.consumed_plan_ids):
        raise RecoveryValidationError("duplicate consumed plans are prohibited")
    if snapshot.attempt_count != len(snapshot.attempt_ids):
        raise RecoveryValidationError("attempt count does not match attempt identifiers")
    if snapshot.current_state is RecoveryControllerState.RESOLVED and snapshot.verification_status is not VerificationStatus.PASSED:
        raise RecoveryValidationError("resolved recovery requires successful verification")
    if snapshot.manual_intervention_required != (snapshot.current_state is RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED):
        if snapshot.manual_intervention_required or snapshot.current_state is RecoveryControllerState.MANUAL_INTERVENTION_REQUIRED:
            raise RecoveryValidationError("manual intervention state is inconsistent")
    if snapshot.circuit_state is CircuitBreakerState.OPEN and (not snapshot.circuit_opened_at or not snapshot.circuit_reset_at):
        raise RecoveryValidationError("open circuit requires opened and reset timestamps")
    if snapshot.circuit_state is CircuitBreakerState.CLOSED and snapshot.circuit_opened_at is not None:
        raise RecoveryValidationError("closed circuit cannot retain an opened timestamp")
