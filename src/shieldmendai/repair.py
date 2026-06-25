"""Deny-by-default repair authorization and deterministic simulation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

import yaml

from .errors import RepairAuthorizationError, RepairValidationError, UnsafeRepairError
from .models import (
    ActionRisk,
    AdapterType,
    ApprovalDecision,
    ApprovalRecord,
    AuthorizationDecision,
    AuthorizationReason,
    AuthorizationReasonCode,
    Confidence,
    CooldownState,
    PolicyMode,
    ReliabilityCategory,
    RepairActionCategory,
    RepairAttemptRecord,
    RepairAuditEvent,
    RepairAuthorizationContext,
    RepairPlan,
    RepairPolicy,
    RepairPrecondition,
    RepairPreconditionType,
    RepairRequest,
    RepairStep,
    RetryState,
    RollbackPlan,
    SecurityCategory,
    Severity,
    ShieldMendAiConfig,
    SimulatedRepairOutcome,
    SimulatedRepairResult,
    Target,
    VerificationPlan,
)
from .redaction import sanitize_message

_T = TypeVar("_T")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
_SENSITIVE_KEY = re.compile(
    r"(token|password|secret|credential|api[_-]?key|private[_-]?key|"
    r"email|phone|wallet|seed|shell|command)",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+")
_PHONE = re.compile(r"\+?\d[\d ()-]{7,}\d")
_FORBIDDEN_PRIVATE = "/root/" + "newbasebot"
_FORBIDDEN_PREFIX = "new" + "base-"

RISK_ORDER = {
    ActionRisk.INFORMATIONAL: 0,
    ActionRisk.LOW: 1,
    ActionRisk.MEDIUM: 2,
    ActionRisk.HIGH: 3,
    ActionRisk.CRITICAL: 4,
    ActionRisk.PROHIBITED: 5,
}
SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
CONFIDENCE_ORDER = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
    Confidence.DETERMINISTIC: 3,
}
ACTION_RISKS = {
    RepairActionCategory.NO_ACTION: ActionRisk.INFORMATIONAL,
    RepairActionCategory.COLLECT_EVIDENCE: ActionRisk.INFORMATIONAL,
    RepairActionCategory.NOTIFY_ONLY: ActionRisk.INFORMATIONAL,
    RepairActionCategory.RECOMMEND_RESTART: ActionRisk.INFORMATIONAL,
    RepairActionCategory.RESTART_ALLOWLISTED_SERVICE: ActionRisk.LOW,
    RepairActionCategory.RECOMMEND_FILE_RESTORE: ActionRisk.INFORMATIONAL,
    RepairActionCategory.RESTORE_KNOWN_GOOD_FILE: ActionRisk.LOW,
    RepairActionCategory.RECOMMEND_PERMISSION_FIX: ActionRisk.INFORMATIONAL,
    RepairActionCategory.APPLY_ALLOWLISTED_PERMISSION_FIX: ActionRisk.MEDIUM,
    RepairActionCategory.RECOMMEND_ROLLBACK: ActionRisk.INFORMATIONAL,
    RepairActionCategory.ROLLBACK_DEPLOYMENT: ActionRisk.MEDIUM,
    RepairActionCategory.PROPOSE_CODE_PATCH: ActionRisk.HIGH,
    RepairActionCategory.APPLY_APPROVED_CODE_PATCH: ActionRisk.PROHIBITED,
    RepairActionCategory.REQUEST_MANUAL_INTERVENTION: ActionRisk.INFORMATIONAL,
}
SIMULATION_SUPPORTED_ACTIONS = frozenset(
    {
        RepairActionCategory.NO_ACTION,
        RepairActionCategory.COLLECT_EVIDENCE,
        RepairActionCategory.NOTIFY_ONLY,
        RepairActionCategory.RESTART_ALLOWLISTED_SERVICE,
        RepairActionCategory.RESTORE_KNOWN_GOOD_FILE,
        RepairActionCategory.APPLY_ALLOWLISTED_PERMISSION_FIX,
        RepairActionCategory.ROLLBACK_DEPLOYMENT,
        RepairActionCategory.REQUEST_MANUAL_INTERVENTION,
    }
)
ROLLBACK_REQUIRED_ACTIONS = frozenset(
    {
        RepairActionCategory.RESTART_ALLOWLISTED_SERVICE,
        RepairActionCategory.RESTORE_KNOWN_GOOD_FILE,
        RepairActionCategory.APPLY_ALLOWLISTED_PERMISSION_FIX,
        RepairActionCategory.ROLLBACK_DEPLOYMENT,
    }
)
RECOMMENDATION_ACTIONS = frozenset(
    {
        RepairActionCategory.RECOMMEND_RESTART,
        RepairActionCategory.RECOMMEND_FILE_RESTORE,
        RepairActionCategory.RECOMMEND_PERMISSION_FIX,
        RepairActionCategory.RECOMMEND_ROLLBACK,
        RepairActionCategory.PROPOSE_CODE_PATCH,
    }
)


@dataclass(frozen=True)
class RepairInput:
    request: RepairRequest
    approval: ApprovalRecord | None
    retry_state: RetryState
    cooldown_state: CooldownState
    verification_plan: VerificationPlan | None
    rollback_plan: RollbackPlan | None
    evidence_present: bool
    finding_still_present: bool
    authorization_at: str


@dataclass(frozen=True)
class RepairSimulationScenario:
    observed_at: str
    action_outcome: str
    verification_outcome: str
    rollback_outcome: str


def action_catalog() -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "action": action.value,
            "risk": ACTION_RISKS.get(action, ActionRisk.PROHIBITED).value,
            "simulation_supported": action in SIMULATION_SUPPORTED_ACTIONS,
            "production_execution_available": False,
        }
        for action in RepairActionCategory
    )


def _mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RepairValidationError(f"{location} must be a mapping")
    return value


def _list(value: Any, location: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RepairValidationError(f"{location} must be a list")
    return value


def _text(
    value: Any,
    location: str,
    *,
    identifier: bool = False,
    reference: bool = False,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RepairValidationError(f"{location} must be a non-empty string")
    result = value.strip()
    if _FORBIDDEN_PRIVATE in result or _FORBIDDEN_PREFIX in result:
        raise RepairValidationError(f"{location} contains a prohibited private reference")
    if identifier and not _ID.fullmatch(result):
        raise RepairValidationError(f"{location} contains unsupported characters")
    if reference and not _REFERENCE.fullmatch(result):
        raise RepairValidationError(f"{location} must be a sanitized reference")
    return result


def _boolean(value: Any, location: str) -> bool:
    if not isinstance(value, bool):
        raise RepairValidationError(f"{location} must be true or false")
    return value


def _integer(value: Any, location: str, *, minimum: int = 0, maximum: int = 100) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RepairValidationError(f"{location} must be an integer between {minimum} and {maximum}")
    return value


def _enum(enum_type: type[_T], value: Any, location: str) -> _T:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        allowed = ", ".join(item.value for item in enum_type)  # type: ignore[attr-defined]
        raise RepairValidationError(f"{location} must be one of: {allowed}") from None


def _timestamp(value: Any, location: str) -> str:
    text = _text(value, location)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise RepairValidationError(f"{location} must be an ISO-8601 timestamp") from None
    if parsed.tzinfo is None:
        raise RepairValidationError(f"{location} must include a timezone")
    return text


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _unique(values: tuple[Any, ...], location: str) -> None:
    if len(values) != len(set(values)):
        raise RepairValidationError(f"{location} contains duplicate entries")


def _reject_sensitive(value: Any, location: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _SENSITIVE_KEY.search(str(key)) and item not in (None, ""):
                raise RepairValidationError(f"{location}.{key} is prohibited")
            _reject_sensitive(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_sensitive(item, f"{location}[{index}]")
    elif isinstance(value, str):
        if (
            _EMAIL.search(value)
            or _FORBIDDEN_PRIVATE in value
            or _FORBIDDEN_PREFIX in value
        ):
            raise RepairValidationError(f"{location} contains prohibited identifying data")


def _load_yaml(path: str | Path, label: str) -> Any:
    try:
        return yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except OSError:
        raise RepairValidationError(f"cannot read {label} file") from None
    except yaml.YAMLError:
        raise RepairValidationError(f"invalid {label} YAML syntax") from None


def parse_repair_policy(data: Any) -> RepairPolicy:
    root = _mapping(data, "repair policy")
    _reject_sensitive(root, "repair policy")
    item = _mapping(root.get("policy", root), "policy")
    actions = tuple(
        _enum(RepairActionCategory, value, "policy.allowed_actions")
        for value in _list(item.get("allowed_actions"), "policy.allowed_actions")
    )
    targets = tuple(
        _text(value, "policy.allowed_target_ids", identifier=True)
        for value in _list(item.get("allowed_target_ids"), "policy.allowed_target_ids")
    )
    adapters = tuple(
        _enum(AdapterType, value, "policy.allowed_adapter_types")
        for value in _list(item.get("allowed_adapter_types"), "policy.allowed_adapter_types")
    )
    pairs: list[tuple[str, RepairActionCategory]] = []
    for index, raw in enumerate(
        _list(item.get("allowed_target_actions"), "policy.allowed_target_actions")
    ):
        pair = _mapping(raw, f"policy.allowed_target_actions[{index}]")
        pairs.append(
            (
                _text(pair.get("target_id"), f"policy.allowed_target_actions[{index}].target_id", identifier=True),
                _enum(
                    RepairActionCategory,
                    pair.get("action"),
                    f"policy.allowed_target_actions[{index}].action",
                ),
            )
        )
    categories = tuple(
        _text(value, "policy.allowed_finding_categories", identifier=True)
        for value in _list(
            item.get("allowed_finding_categories"), "policy.allowed_finding_categories"
        )
    )
    for location, values in (
        ("policy.allowed_actions", actions),
        ("policy.allowed_target_ids", targets),
        ("policy.allowed_adapter_types", adapters),
        ("policy.allowed_target_actions", tuple(pairs)),
        ("policy.allowed_finding_categories", categories),
    ):
        _unique(values, location)
    raw_allowlists = [*targets, *(action.value for action in actions)]
    if any("*" in value for value in raw_allowlists):
        raise RepairValidationError("repair allowlists must use exact values and cannot contain wildcards")
    if any(target not in targets or action not in actions for target, action in pairs):
        raise RepairValidationError("target/action pairs must be present in both explicit allowlists")
    minimum_severity = _enum(
        Severity, item.get("minimum_severity", "info"), "policy.minimum_severity"
    )
    maximum_severity = _enum(
        Severity, item.get("maximum_severity", "critical"), "policy.maximum_severity"
    )
    if SEVERITY_ORDER[minimum_severity] > SEVERITY_ORDER[maximum_severity]:
        raise RepairValidationError("policy severity range is contradictory")
    return RepairPolicy(
        id=_text(item.get("id"), "policy.id", identifier=True),
        mode=_enum(PolicyMode, item.get("mode"), "policy.mode"),
        allowed_actions=actions,
        allowed_target_ids=targets,
        allowed_adapter_types=adapters,
        allowed_target_actions=tuple(pairs),
        maximum_risk=_enum(
            ActionRisk, item.get("maximum_risk", "informational"), "policy.maximum_risk"
        ),
        allowed_finding_categories=categories,
        minimum_severity=minimum_severity,
        maximum_severity=maximum_severity,
        minimum_confidence=_enum(
            Confidence, item.get("minimum_confidence", "low"), "policy.minimum_confidence"
        ),
        retry_limit=_integer(item.get("retry_limit", 0), "policy.retry_limit"),
        cooldown_seconds=_integer(
            item.get("cooldown_seconds", 0), "policy.cooldown_seconds", maximum=86400
        ),
        verification_delay_seconds=_integer(
            item.get("verification_delay_seconds", 0),
            "policy.verification_delay_seconds",
            maximum=86400,
        ),
        require_pre_repair_evidence=_boolean(
            item.get("require_pre_repair_evidence", True),
            "policy.require_pre_repair_evidence",
        ),
        require_verification=_boolean(
            item.get("require_verification", True), "policy.require_verification"
        ),
        rollback_on_verification_failure=_boolean(
            item.get("rollback_on_verification_failure", True),
            "policy.rollback_on_verification_failure",
        ),
    )


def load_repair_policy(path: str | Path) -> RepairPolicy:
    return parse_repair_policy(_load_yaml(path, "repair policy"))


def _parse_category(value: Any) -> ReliabilityCategory | SecurityCategory:
    try:
        return ReliabilityCategory(value)
    except (TypeError, ValueError):
        try:
            return SecurityCategory(value)
        except (TypeError, ValueError):
            raise RepairValidationError("request.finding_category is unknown") from None


def _parse_verification(data: Any, target_id: str, adapter: AdapterType) -> VerificationPlan | None:
    if data is None:
        return None
    item = _mapping(data, "verification_plan")
    if item.get("target_id") != target_id or item.get("adapter_type") != adapter.value:
        raise RepairValidationError("verification plan target or adapter does not match request")
    checks = tuple(
        _text(value, "verification_plan.checks_to_repeat", identifier=True)
        for value in _list(item.get("checks_to_repeat"), "verification_plan.checks_to_repeat")
    )
    success = tuple(
        _text(value, "verification_plan.success_criteria")
        for value in _list(item.get("success_criteria"), "verification_plan.success_criteria")
    )
    failure = tuple(
        _text(value, "verification_plan.failure_criteria")
        for value in _list(item.get("failure_criteria"), "verification_plan.failure_criteria")
    )
    if not checks or not success or not failure:
        raise RepairValidationError("verification plan checks and criteria must not be empty")
    return VerificationPlan(
        verification_id=_text(item.get("verification_id"), "verification_plan.verification_id", identifier=True),
        target_id=target_id,
        adapter_type=adapter,
        checks_to_repeat=checks,
        expected_status=_text(item.get("expected_status"), "verification_plan.expected_status", identifier=True),
        delay_seconds=_integer(item.get("delay_seconds", 0), "verification_plan.delay_seconds", maximum=86400),
        maximum_attempts=_integer(item.get("maximum_attempts", 1), "verification_plan.maximum_attempts", minimum=1),
        success_criteria=success,
        failure_criteria=failure,
        rollback_trigger=(
            _text(item.get("rollback_trigger"), "verification_plan.rollback_trigger")
            if item.get("rollback_trigger") is not None
            else None
        ),
        manual_review_trigger=(
            _text(item.get("manual_review_trigger"), "verification_plan.manual_review_trigger")
            if item.get("manual_review_trigger") is not None
            else None
        ),
    )


def _parse_rollback(data: Any, action: RepairActionCategory) -> RollbackPlan | None:
    if data is None:
        return None
    item = _mapping(data, "rollback_plan")
    original = _enum(
        RepairActionCategory, item.get("original_action"), "rollback_plan.original_action"
    )
    if original is not action:
        raise RepairValidationError("rollback plan action does not match request")
    preconditions = tuple(
        _text(value, "rollback_plan.preconditions", identifier=True)
        for value in _list(item.get("preconditions"), "rollback_plan.preconditions")
    )
    checks = tuple(
        _text(value, "rollback_plan.verification_after_rollback", identifier=True)
        for value in _list(
            item.get("verification_after_rollback"),
            "rollback_plan.verification_after_rollback",
        )
    )
    if not preconditions or not checks:
        raise RepairValidationError("rollback plan preconditions and verification must not be empty")
    return RollbackPlan(
        rollback_id=_text(item.get("rollback_id"), "rollback_plan.rollback_id", identifier=True),
        original_action=original,
        rollback_action=_text(item.get("rollback_action"), "rollback_plan.rollback_action", identifier=True),
        required_backup_reference=(
            _text(item.get("required_backup_reference"), "rollback_plan.required_backup_reference", reference=True)
            if item.get("required_backup_reference") is not None
            else None
        ),
        known_good_reference=(
            _text(item.get("known_good_reference"), "rollback_plan.known_good_reference", reference=True)
            if item.get("known_good_reference") is not None
            else None
        ),
        preconditions=preconditions,
        verification_after_rollback=checks,
        maximum_attempts=_integer(item.get("maximum_attempts", 1), "rollback_plan.maximum_attempts", minimum=1),
        manual_intervention_fallback=_text(
            item.get("manual_intervention_fallback"),
            "rollback_plan.manual_intervention_fallback",
        ),
    )


def _parse_approval(data: Any, request: RepairRequest) -> ApprovalRecord | None:
    if data is None:
        return None
    item = _mapping(data, "approval")
    approver = _text(item.get("approver_reference"), "approval.approver_reference", reference=True)
    if _EMAIL.search(approver) or _PHONE.search(approver):
        raise RepairValidationError("approval.approver_reference must not contain personal contact data")
    return ApprovalRecord(
        approval_id=_text(item.get("approval_id"), "approval.approval_id", identifier=True),
        request_id=_text(item.get("request_id"), "approval.request_id", identifier=True),
        approver_reference=approver,
        decision=_enum(ApprovalDecision, item.get("decision"), "approval.decision"),
        approved_action=_enum(
            RepairActionCategory, item.get("approved_action"), "approval.approved_action"
        ),
        issued_at=_timestamp(item.get("issued_at"), "approval.issued_at"),
        expires_at=_timestamp(item.get("expires_at"), "approval.expires_at"),
        target_scope=tuple(
            _text(value, "approval.target_scope", identifier=True)
            for value in _list(item.get("target_scope"), "approval.target_scope")
        ),
        one_time=_boolean(item.get("one_time", True), "approval.one_time"),
        reason=_text(item.get("reason"), "approval.reason"),
        consumed_at=(
            _timestamp(item.get("consumed_at"), "approval.consumed_at")
            if item.get("consumed_at") is not None
            else None
        ),
        revoked=_boolean(item.get("revoked", False), "approval.revoked"),
    )


def parse_repair_input(data: Any) -> RepairInput:
    root = _mapping(data, "repair input")
    _reject_sensitive(root, "repair input")
    item = _mapping(root.get("request"), "request")
    action = _enum(RepairActionCategory, item.get("requested_action"), "request.requested_action")
    request = RepairRequest(
        request_id=_text(item.get("request_id"), "request.request_id", identifier=True),
        incident_id=_text(item.get("incident_id"), "request.incident_id", identifier=True),
        target_id=_text(item.get("target_id"), "request.target_id", identifier=True),
        adapter_type=_enum(AdapterType, item.get("adapter_type"), "request.adapter_type"),
        finding_category=_parse_category(item.get("finding_category")),
        finding_severity=_enum(Severity, item.get("finding_severity"), "request.finding_severity"),
        finding_confidence=_enum(
            Confidence, item.get("finding_confidence"), "request.finding_confidence"
        ),
        requested_action=action,
        requested_at=_timestamp(item.get("requested_at"), "request.requested_at"),
        expires_at=_timestamp(item.get("expires_at"), "request.expires_at"),
        policy_reference=_text(item.get("policy_reference"), "request.policy_reference", identifier=True),
        evidence_reference=(
            _text(item.get("evidence_reference"), "request.evidence_reference", reference=True)
            if item.get("evidence_reference") is not None
            else None
        ),
        simulation=_boolean(item.get("simulation"), "request.simulation"),
        consumed_at=(
            _timestamp(item.get("consumed_at"), "request.consumed_at")
            if item.get("consumed_at") is not None
            else None
        ),
    )
    retry = _mapping(root.get("retry_state", {}), "retry_state")
    cooldown = _mapping(root.get("cooldown_state", {}), "cooldown_state")
    retry_state = RetryState(
        attempts=_integer(retry.get("attempts", 0), "retry_state.attempts"),
        limit=_integer(retry.get("limit", 0), "retry_state.limit"),
    )
    cooldown_state = CooldownState(
        last_attempt_at=(
            _timestamp(cooldown.get("last_attempt_at"), "cooldown_state.last_attempt_at")
            if cooldown.get("last_attempt_at") is not None
            else None
        ),
        cooldown_seconds=_integer(
            cooldown.get("cooldown_seconds", 0),
            "cooldown_state.cooldown_seconds",
            maximum=86400,
        ),
        elapsed=_boolean(cooldown.get("elapsed", True), "cooldown_state.elapsed"),
    )
    return RepairInput(
        request=request,
        approval=_parse_approval(root.get("approval"), request),
        retry_state=retry_state,
        cooldown_state=cooldown_state,
        verification_plan=_parse_verification(
            root.get("verification_plan"), request.target_id, request.adapter_type
        ),
        rollback_plan=_parse_rollback(root.get("rollback_plan"), action),
        evidence_present=_boolean(root.get("evidence_present", False), "evidence_present"),
        finding_still_present=_boolean(
            root.get("finding_still_present", True), "finding_still_present"
        ),
        authorization_at=_timestamp(root.get("authorization_at"), "authorization_at"),
    )


def load_repair_input(path: str | Path) -> RepairInput:
    return parse_repair_input(_load_yaml(path, "repair request"))


def parse_repair_scenario(data: Any) -> RepairSimulationScenario:
    root = _mapping(data, "repair scenario")
    _reject_sensitive(root, "repair scenario")
    allowed_action = {"success", "failure"}
    allowed_verification = {"success", "failure"}
    allowed_rollback = {"not_required", "success", "failure"}
    action = _text(root.get("action_outcome"), "scenario.action_outcome", identifier=True)
    verification = _text(
        root.get("verification_outcome"), "scenario.verification_outcome", identifier=True
    )
    rollback = _text(root.get("rollback_outcome"), "scenario.rollback_outcome", identifier=True)
    if action not in allowed_action or verification not in allowed_verification or rollback not in allowed_rollback:
        raise RepairValidationError("repair scenario contains an unsupported deterministic outcome")
    return RepairSimulationScenario(
        observed_at=_timestamp(root.get("observed_at"), "scenario.observed_at"),
        action_outcome=action,
        verification_outcome=verification,
        rollback_outcome=rollback,
    )


def load_repair_scenario(path: str | Path) -> RepairSimulationScenario:
    return parse_repair_scenario(_load_yaml(path, "repair scenario"))


def _reason(
    reasons: list[AuthorizationReason],
    code: AuthorizationReasonCode,
    explanation: str,
) -> None:
    reasons.append(AuthorizationReason(code, sanitize_message(explanation)))


def _approval_reasons(
    request: RepairRequest,
    approval: ApprovalRecord | None,
    now: datetime,
    reasons: list[AuthorizationReason],
) -> None:
    if approval is None:
        _reason(reasons, AuthorizationReasonCode.APPROVAL_MISSING, "Required explicit approval is missing.")
        return
    if approval.revoked or approval.decision is ApprovalDecision.REVOKED:
        _reason(reasons, AuthorizationReasonCode.APPROVAL_REVOKED, "Approval is revoked.")
    elif approval.decision is not ApprovalDecision.APPROVED:
        _reason(reasons, AuthorizationReasonCode.APPROVAL_INVALID, "Approval decision is not approved.")
    if _time(approval.expires_at) <= now:
        _reason(reasons, AuthorizationReasonCode.APPROVAL_EXPIRED, "Approval has expired.")
    if _time(approval.issued_at) > now:
        _reason(reasons, AuthorizationReasonCode.APPROVAL_INVALID, "Approval is not yet valid.")
    if approval.request_id != request.request_id:
        _reason(reasons, AuthorizationReasonCode.APPROVAL_INVALID, "Approval request scope does not match.")
    if approval.approved_action is not request.requested_action:
        _reason(reasons, AuthorizationReasonCode.APPROVAL_INVALID, "Approval action does not match.")
    if request.target_id not in approval.target_scope:
        _reason(reasons, AuthorizationReasonCode.APPROVAL_INVALID, "Approval target scope does not match.")
    if approval.one_time and approval.consumed_at is not None:
        _reason(reasons, AuthorizationReasonCode.APPROVAL_CONSUMED, "One-time approval was already consumed.")


def _finding_supports(request: RepairRequest) -> bool:
    category = request.finding_category
    action = request.requested_action
    if action in {
        RepairActionCategory.NO_ACTION,
        RepairActionCategory.COLLECT_EVIDENCE,
        RepairActionCategory.NOTIFY_ONLY,
        RepairActionCategory.REQUEST_MANUAL_INTERVENTION,
    }:
        return True
    if action in {
        RepairActionCategory.RECOMMEND_RESTART,
        RepairActionCategory.RESTART_ALLOWLISTED_SERVICE,
    }:
        return category in {
            ReliabilityCategory.SERVICE_STOPPED,
            ReliabilityCategory.SERVICE_FAILED,
        }
    if action in {
        RepairActionCategory.RECOMMEND_FILE_RESTORE,
        RepairActionCategory.RESTORE_KNOWN_GOOD_FILE,
    }:
        return category in {
            ReliabilityCategory.FILE_MISSING,
            ReliabilityCategory.UNEXPECTED_FILE_CHANGE,
        }
    if action in {
        RepairActionCategory.RECOMMEND_PERMISSION_FIX,
        RepairActionCategory.APPLY_ALLOWLISTED_PERMISSION_FIX,
    }:
        return category in {
            ReliabilityCategory.INCORRECT_PERMISSIONS,
            ReliabilityCategory.INCORRECT_OWNERSHIP,
        }
    if action in {
        RepairActionCategory.RECOMMEND_ROLLBACK,
        RepairActionCategory.ROLLBACK_DEPLOYMENT,
    }:
        return category is ReliabilityCategory.DEPLOYMENT_FAILURE
    return action is RepairActionCategory.PROPOSE_CODE_PATCH


def authorize_repair(
    request: RepairRequest,
    context: RepairAuthorizationContext,
) -> AuthorizationDecision:
    reasons: list[AuthorizationReason] = []
    target = context.target
    policy = context.policy
    now = _time(context.now)
    risk = ACTION_RISKS.get(request.requested_action, ActionRisk.PROHIBITED)
    if target is None:
        _reason(reasons, AuthorizationReasonCode.TARGET_NOT_FOUND, "Target is unknown.")
    else:
        if not target.enabled:
            _reason(reasons, AuthorizationReasonCode.TARGET_DISABLED, "Target is disabled.")
        if target.id not in policy.allowed_target_ids:
            _reason(reasons, AuthorizationReasonCode.TARGET_NOT_ALLOWLISTED, "Target is not explicitly allowlisted.")
        if target.adapter_type not in policy.allowed_adapter_types:
            _reason(reasons, AuthorizationReasonCode.ADAPTER_MISMATCH, "Target adapter is not allowlisted.")
        if target.adapter_type is not request.adapter_type:
            _reason(reasons, AuthorizationReasonCode.ADAPTER_MISMATCH, "Request adapter does not match target.")
    if request.policy_reference != policy.id:
        _reason(reasons, AuthorizationReasonCode.POLICY_REFERENCE_MISMATCH, "Policy reference does not match.")
    if request.requested_action not in policy.allowed_actions:
        _reason(reasons, AuthorizationReasonCode.ACTION_NOT_ALLOWLISTED, "Action is not explicitly allowlisted.")
    if (request.target_id, request.requested_action) not in policy.allowed_target_actions:
        _reason(
            reasons,
            AuthorizationReasonCode.TARGET_ACTION_NOT_ALLOWLISTED,
            "Exact target/action pair is not explicitly allowlisted.",
        )
    if not _finding_supports(request):
        _reason(reasons, AuthorizationReasonCode.FINDING_ACTION_MISMATCH, "Finding category does not support action.")
    if (
        policy.allowed_finding_categories
        and request.finding_category.value not in policy.allowed_finding_categories
    ):
        _reason(reasons, AuthorizationReasonCode.FINDING_ACTION_MISMATCH, "Finding category is not allowlisted.")
    severity = SEVERITY_ORDER[request.finding_severity]
    if not SEVERITY_ORDER[policy.minimum_severity] <= severity <= SEVERITY_ORDER[policy.maximum_severity]:
        _reason(reasons, AuthorizationReasonCode.SEVERITY_NOT_PERMITTED, "Finding severity is outside policy range.")
    if CONFIDENCE_ORDER[request.finding_confidence] < CONFIDENCE_ORDER[policy.minimum_confidence]:
        _reason(reasons, AuthorizationReasonCode.CONFIDENCE_NOT_PERMITTED, "Finding confidence is below policy minimum.")
    if risk is ActionRisk.PROHIBITED:
        _reason(reasons, AuthorizationReasonCode.ACTION_PROHIBITED, "Action is prohibited in Phase 4.")
    elif RISK_ORDER[risk] > RISK_ORDER[policy.maximum_risk]:
        _reason(reasons, AuthorizationReasonCode.RISK_TOO_HIGH, "Action risk exceeds policy maximum.")
    if request.requested_action not in SIMULATION_SUPPORTED_ACTIONS:
        _reason(reasons, AuthorizationReasonCode.ACTION_PROHIBITED, "Action has no Phase 4 simulation executor.")
    if policy.mode is PolicyMode.OBSERVE_ONLY:
        _reason(reasons, AuthorizationReasonCode.POLICY_OBSERVE_ONLY, "Observe-only policy denies execution.")
    elif policy.mode is PolicyMode.RECOMMEND:
        _reason(reasons, AuthorizationReasonCode.POLICY_RECOMMEND_ONLY, "Recommend policy denies execution.")
    elif policy.mode is PolicyMode.REQUIRE_APPROVAL:
        _approval_reasons(request, context.approval, now, reasons)
    elif policy.mode is PolicyMode.AUTO_REPAIR_LOW_RISK and risk not in {
        ActionRisk.INFORMATIONAL,
        ActionRisk.LOW,
    }:
        _reason(reasons, AuthorizationReasonCode.RISK_TOO_HIGH, "Automatic low-risk policy rejects this risk.")
    if context.retry_state.attempts >= context.retry_state.limit:
        _reason(reasons, AuthorizationReasonCode.RETRY_LIMIT_EXCEEDED, "Retry budget is exhausted.")
    if not context.cooldown_state.elapsed:
        _reason(reasons, AuthorizationReasonCode.COOLDOWN_NOT_ELAPSED, "Cooldown has not elapsed.")
    if policy.require_pre_repair_evidence and not context.evidence_present:
        _reason(reasons, AuthorizationReasonCode.EVIDENCE_MISSING, "Required evidence reference is missing.")
    if policy.require_verification and context.verification_plan is None:
        _reason(reasons, AuthorizationReasonCode.VERIFICATION_MISSING, "Verification plan is missing.")
    if request.requested_action in ROLLBACK_REQUIRED_ACTIONS and context.rollback_plan is None:
        _reason(reasons, AuthorizationReasonCode.ROLLBACK_MISSING, "Required rollback plan is missing.")
    if _time(request.expires_at) <= now:
        _reason(reasons, AuthorizationReasonCode.REQUEST_EXPIRED, "Repair request has expired.")
    if request.consumed_at is not None:
        _reason(reasons, AuthorizationReasonCode.REQUEST_CONSUMED, "Repair request was already consumed.")
    if not request.simulation:
        _reason(reasons, AuthorizationReasonCode.SIMULATION_REQUIRED, "Simulation mode must be enabled.")
    if context.production_execution_available:
        _reason(reasons, AuthorizationReasonCode.PRODUCTION_UNAVAILABLE, "Production execution must remain unavailable.")
    permitted = not reasons
    if permitted:
        _reason(reasons, AuthorizationReasonCode.AUTHORIZED, "All explicit simulation authorization gates passed.")
    return AuthorizationDecision(
        decision_id=f"authorization-{request.request_id}",
        request_id=request.request_id,
        target_id=request.target_id,
        action=request.requested_action,
        risk=risk,
        permitted=permitted,
        simulation_permitted=permitted,
        recommendation_only=policy.mode is PolicyMode.RECOMMEND,
        reasons=tuple(reasons),
        approval_reference=context.approval.approval_id if context.approval else None,
        decided_at=context.now,
    )


def authorization_context(
    config: ShieldMendAiConfig,
    repair_input: RepairInput,
    policy: RepairPolicy,
) -> RepairAuthorizationContext:
    target = next(
        (item for item in config.targets if item.id == repair_input.request.target_id),
        None,
    )
    return RepairAuthorizationContext(
        target=target,
        policy=policy,
        approval=repair_input.approval,
        retry_state=repair_input.retry_state,
        cooldown_state=repair_input.cooldown_state,
        verification_plan=repair_input.verification_plan,
        rollback_plan=repair_input.rollback_plan,
        evidence_present=repair_input.evidence_present,
        finding_still_present=repair_input.finding_still_present,
        now=repair_input.authorization_at,
        production_execution_available=False,
    )


def create_repair_plan(
    request: RepairRequest,
    context: RepairAuthorizationContext,
    decision: AuthorizationDecision,
) -> RepairPlan:
    if not decision.permitted or not decision.simulation_permitted:
        raise RepairAuthorizationError("repair planning requires successful simulation authorization")
    if context.verification_plan is None:
        raise RepairAuthorizationError("repair planning requires a verification plan")
    preconditions = [
        RepairPrecondition(RepairPreconditionType.FINDING_STILL_PRESENT, context.finding_still_present, "Scenario states the finding remains present."),
        RepairPrecondition(RepairPreconditionType.TARGET_IDENTITY_MATCHES, context.target is not None and context.target.id == request.target_id, "Configured target identity matches request."),
        RepairPrecondition(RepairPreconditionType.TARGET_IS_ALLOWLISTED, request.target_id in context.policy.allowed_target_ids, "Exact target ID is allowlisted."),
        RepairPrecondition(RepairPreconditionType.ACTION_IS_ALLOWLISTED, request.requested_action in context.policy.allowed_actions, "Typed action is allowlisted."),
        RepairPrecondition(RepairPreconditionType.RETRY_BUDGET_AVAILABLE, context.retry_state.attempts < context.retry_state.limit, "Retry budget remains."),
        RepairPrecondition(RepairPreconditionType.COOLDOWN_ELAPSED, context.cooldown_state.elapsed, "Scenario-controlled cooldown elapsed."),
        RepairPrecondition(RepairPreconditionType.APPROVAL_VALID, context.policy.mode is not PolicyMode.REQUIRE_APPROVAL or context.approval is not None, "Required approval gate passed."),
        RepairPrecondition(RepairPreconditionType.VERIFICATION_CONFIGURED, True, "Verification plan is configured."),
        RepairPrecondition(RepairPreconditionType.SIMULATION_ONLY, request.simulation, "Production execution is unavailable."),
    ]
    if request.requested_action in ROLLBACK_REQUIRED_ACTIONS:
        preconditions.append(
            RepairPrecondition(
                RepairPreconditionType.ROLLBACK_AVAILABLE,
                context.rollback_plan is not None,
                "A deterministic rollback plan is configured.",
            )
        )
    if request.requested_action is RepairActionCategory.RESTORE_KNOWN_GOOD_FILE:
        preconditions.append(
            RepairPrecondition(
                RepairPreconditionType.KNOWN_GOOD_SOURCE_AVAILABLE,
                context.rollback_plan is not None
                and context.rollback_plan.known_good_reference is not None,
                "A sanitized known-good reference is configured.",
            )
        )
    if not all(item.satisfied for item in preconditions):
        raise RepairAuthorizationError("repair plan contains an unsatisfied precondition")
    steps = (
        RepairStep(
            step_id=f"{request.request_id}-step-1",
            action=request.requested_action.value,
            description=f"Simulate {request.requested_action.value} for exact target {request.target_id}.",
        ),
        RepairStep(
            step_id=f"{request.request_id}-step-2",
            action="simulate_verification",
            description="Evaluate deterministic verification outcome supplied by scenario data.",
        ),
    )
    return RepairPlan(
        plan_id=f"plan-{request.request_id}",
        request=request,
        authorization=decision,
        risk=decision.risk,
        created_at=context.now,
        expires_at=request.expires_at,
        preconditions=tuple(preconditions),
        steps=steps,
        verification_plan=context.verification_plan,
        rollback_plan=context.rollback_plan,
        approval_required=context.policy.mode is PolicyMode.REQUIRE_APPROVAL,
    )


class SimulationRepairExecutor:
    """Consumes authorized plans and returns records without live side effects."""

    def execute(
        self,
        plan: RepairPlan,
        scenario: RepairSimulationScenario,
    ) -> SimulatedRepairResult:
        request = plan.request
        decision = plan.authorization
        if not plan.simulation or not request.simulation:
            raise UnsafeRepairError("simulation mode is required")
        if plan.production_execution_available:
            raise UnsafeRepairError("production execution must be unavailable")
        if not decision.permitted or not decision.simulation_permitted:
            raise UnsafeRepairError("authorization does not permit simulation")
        if plan.approval_required and not decision.approval_reference:
            raise UnsafeRepairError("required approval is missing")
        if decision.request_id != request.request_id or decision.target_id != request.target_id:
            raise UnsafeRepairError("plan target does not match authorization")
        if decision.action is not request.requested_action:
            raise UnsafeRepairError("plan action does not match authorization")
        if _time(plan.expires_at) <= _time(scenario.observed_at):
            raise UnsafeRepairError("repair plan has expired")
        if request.consumed_at is not None:
            raise UnsafeRepairError("repair request was already consumed")
        if plan.verification_plan is None:
            raise UnsafeRepairError("verification plan is missing")
        if request.requested_action in ROLLBACK_REQUIRED_ACTIONS and plan.rollback_plan is None:
            raise UnsafeRepairError("required rollback plan is missing")
        if request.requested_action not in SIMULATION_SUPPORTED_ACTIONS:
            raise UnsafeRepairError("unsupported repair action")

        verification = (
            SimulatedRepairOutcome.SIMULATED_VERIFICATION_SUCCESS.value
            if scenario.verification_outcome == "success"
            else SimulatedRepairOutcome.SIMULATED_VERIFICATION_FAILURE.value
        )
        rollback = "not_required"
        manual = request.requested_action is RepairActionCategory.REQUEST_MANUAL_INTERVENTION
        if scenario.action_outcome == "failure":
            outcome = SimulatedRepairOutcome.AUTHORIZED_AND_SIMULATED_FAILURE
        elif scenario.verification_outcome == "success":
            outcome = SimulatedRepairOutcome.AUTHORIZED_AND_SIMULATED_SUCCESS
        elif plan.rollback_plan is None:
            outcome = SimulatedRepairOutcome.MANUAL_INTERVENTION_REQUIRED
            manual = True
        elif scenario.rollback_outcome == "success":
            rollback = SimulatedRepairOutcome.SIMULATED_ROLLBACK_SUCCESS.value
            outcome = SimulatedRepairOutcome.AUTHORIZED_AND_SIMULATED_FAILURE
        else:
            rollback = SimulatedRepairOutcome.SIMULATED_ROLLBACK_FAILURE.value
            outcome = SimulatedRepairOutcome.MANUAL_INTERVENTION_REQUIRED
            manual = True
        attempt = RepairAttemptRecord(
            attempt_id=f"attempt-{request.request_id}",
            request_id=request.request_id,
            plan_id=plan.plan_id,
            target_id=request.target_id,
            action=request.requested_action,
            risk=plan.risk,
            started_at=scenario.observed_at,
            completed_at=scenario.observed_at,
            simulation=True,
            steps=plan.steps,
            verification_outcome=verification,
            rollback_outcome=rollback,
            final_outcome=outcome,
        )
        event = RepairAuditEvent(
            event_id=f"audit-{request.request_id}",
            request_id=request.request_id,
            incident_id=request.incident_id,
            target_id=request.target_id,
            timestamp=scenario.observed_at,
            event_type="simulated_repair_attempt",
            authorization_outcome="authorized",
            reason_codes=tuple(reason.code for reason in decision.reasons),
            policy_reference=request.policy_reference,
            action=request.requested_action,
            risk=plan.risk,
            simulation=True,
            approval_reference=decision.approval_reference,
            verification_outcome=verification,
            rollback_outcome=rollback,
            final_outcome=outcome,
        )
        return SimulatedRepairResult(
            request_id=request.request_id,
            plan_id=plan.plan_id,
            authorized=True,
            simulation=True,
            production_execution_available=False,
            outcome=outcome,
            steps=plan.steps,
            verification_outcome=verification,
            rollback_outcome=rollback,
            manual_intervention_required=manual,
            attempt_record=attempt,
            audit_events=(event,),
        )
