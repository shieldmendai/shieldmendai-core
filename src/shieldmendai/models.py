"""Typed, execution-free ShieldMendAi domain models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class AdapterType(str, Enum):
    SYSTEMD_SERVICE = "systemd_service"
    SYSTEMD_TIMER = "systemd_timer"
    PROCESS = "process"
    PID_FILE = "pid_file"
    TCP = "tcp"
    HTTP = "http"
    FILE = "file"
    JSON_FILE = "json_file"
    YAML_FILE = "yaml_file"
    TOML_FILE = "toml_file"
    EXECUTABLE_CHECK = "executable_check"
    DATABASE = "database"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    WINDOWS_SERVICE = "windows_service"
    PLUGIN = "plugin"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ObservationStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"
    OBSERVATION_ERROR = "observation_error"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DETERMINISTIC = "deterministic"


class ErrorClassification(str, Enum):
    NONE = "none"
    VALIDATION = "validation"
    UNSUPPORTED = "unsupported"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    PARSE_ERROR = "parse_error"
    PERMISSION = "permission"
    MISMATCH = "mismatch"
    SIMULATED_FAILURE = "simulated_failure"


class PolicyMode(str, Enum):
    OBSERVE_ONLY = "observe_only"
    RECOMMEND = "recommend"
    REQUIRE_APPROVAL = "require_approval"
    AUTO_REPAIR_LOW_RISK = "auto_repair_low_risk"
    AUTO_REPAIR_ALLOWLISTED = "auto_repair_allowlisted"


class ReliabilityCategory(str, Enum):
    SERVICE_STOPPED = "service_stopped"
    SERVICE_FAILED = "service_failed"
    TIMER_FAILED = "timer_failed"
    PROCESS_MISSING = "process_missing"
    PROCESS_UNHEALTHY = "process_unhealthy"
    RESTART_LOOP = "restart_loop"
    HTTP_UNHEALTHY = "http_unhealthy"
    TCP_UNREACHABLE = "tcp_unreachable"
    FILE_MISSING = "file_missing"
    FILE_STALE = "file_stale"
    INVALID_JSON = "invalid_json"
    INVALID_YAML = "invalid_yaml"
    INVALID_TOML = "invalid_toml"
    INVALID_CONFIGURATION = "invalid_configuration"
    INCORRECT_PERMISSIONS = "incorrect_permissions"
    INCORRECT_OWNERSHIP = "incorrect_ownership"
    DISK_PRESSURE = "disk_pressure"
    MEMORY_PRESSURE = "memory_pressure"
    CPU_PRESSURE = "cpu_pressure"
    DEPENDENCY_FAILURE = "dependency_failure"
    DEPLOYMENT_FAILURE = "deployment_failure"
    CERTIFICATE_EXPIRING = "certificate_expiring"
    CERTIFICATE_EXPIRED = "certificate_expired"
    DATABASE_UNREACHABLE = "database_unreachable"
    APPLICATION_TEST_FAILURE = "application_test_failure"
    UNEXPECTED_FILE_CHANGE = "unexpected_file_change"
    UNKNOWN_FAILURE = "unknown_failure"


class SecurityCategory(str, Enum):
    OPERATING_SYSTEM_VULNERABILITY = "operating_system_vulnerability"
    APPLICATION_DEPENDENCY_VULNERABILITY = "application_dependency_vulnerability"
    INSECURE_CONFIGURATION = "insecure_configuration"
    EXPOSED_SERVICE = "exposed_service"
    EXPOSED_PORT = "exposed_port"
    DANGEROUS_PERMISSIONS = "dangerous_permissions"
    SECRET_EXPOSURE_INDICATOR = "secret_exposure_indicator"
    OUTDATED_SOFTWARE = "outdated_software"
    WEAK_TLS_CONFIGURATION = "weak_tls_configuration"
    CERTIFICATE_PROBLEM = "certificate_problem"
    UNAUTHORIZED_FILE_CHANGE = "unauthorized_file_change"
    SUSPICIOUS_PROCESS = "suspicious_process"
    SUSPICIOUS_SERVICE_BEHAVIOR = "suspicious_service_behavior"
    SECURITY_BASELINE_VIOLATION = "security_baseline_violation"
    UNKNOWN_SECURITY_FINDING = "unknown_security_finding"


class LifecycleStatus(str, Enum):
    SUSPECTED = "suspected"
    DETECTED = "detected"
    CONFIRMED = "confirmed"
    PROPOSED_REPAIR = "proposed_repair"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED_REPAIR = "approved_repair"
    AUTOMATICALLY_PERMITTED_REPAIR = "automatically_permitted_repair"
    REPAIR_ATTEMPTED = "repair_attempted"
    REPAIR_SUCCESSFUL = "repair_successful"
    REPAIR_UNSUCCESSFUL = "repair_unsuccessful"
    VERIFICATION_SUCCESSFUL = "verification_successful"
    VERIFICATION_FAILED = "verification_failed"
    ROLLBACK_COMPLETED = "rollback_completed"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"


class ApprovalStatus(str, Enum):
    NOT_REQUIRED = "not_required"
    NOT_REQUESTED = "not_requested"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    AUTOMATICALLY_PERMITTED = "automatically_permitted"


class VerificationResult(str, Enum):
    NOT_RUN = "not_run"
    SUCCESSFUL = "successful"
    FAILED = "failed"


class RollbackStatus(str, Enum):
    NOT_REQUIRED = "not_required"
    NOT_ATTEMPTED = "not_attempted"
    COMPLETED = "completed"
    FAILED = "failed"


class RepairActionCategory(str, Enum):
    NO_ACTION = "no_action"
    COLLECT_EVIDENCE = "collect_evidence"
    NOTIFY_ONLY = "notify_only"
    RECOMMEND_RESTART = "recommend_restart"
    RESTART_ALLOWLISTED_SERVICE = "restart_allowlisted_service"
    RECOMMEND_FILE_RESTORE = "recommend_file_restore"
    RESTORE_KNOWN_GOOD_FILE = "restore_known_good_file"
    RECOMMEND_PERMISSION_FIX = "recommend_permission_fix"
    APPLY_ALLOWLISTED_PERMISSION_FIX = "apply_allowlisted_permission_fix"
    RECOMMEND_ROLLBACK = "recommend_rollback"
    ROLLBACK_DEPLOYMENT = "rollback_deployment"
    PROPOSE_CODE_PATCH = "propose_code_patch"
    APPLY_APPROVED_CODE_PATCH = "apply_approved_code_patch"
    REQUEST_MANUAL_INTERVENTION = "request_manual_intervention"


class ActionRisk(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    PROHIBITED = "prohibited"


class ApprovalDecision(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PENDING = "pending"


class AuthorizationReasonCode(str, Enum):
    AUTHORIZED = "authorized"
    POLICY_OBSERVE_ONLY = "policy_observe_only"
    POLICY_RECOMMEND_ONLY = "policy_recommend_only"
    TARGET_NOT_FOUND = "target_not_found"
    TARGET_DISABLED = "target_disabled"
    TARGET_NOT_ALLOWLISTED = "target_not_allowlisted"
    ACTION_NOT_ALLOWLISTED = "action_not_allowlisted"
    TARGET_ACTION_NOT_ALLOWLISTED = "target_action_not_allowlisted"
    ADAPTER_MISMATCH = "adapter_mismatch"
    FINDING_ACTION_MISMATCH = "finding_action_mismatch"
    SEVERITY_NOT_PERMITTED = "severity_not_permitted"
    CONFIDENCE_NOT_PERMITTED = "confidence_not_permitted"
    RISK_TOO_HIGH = "risk_too_high"
    ACTION_PROHIBITED = "action_prohibited"
    APPROVAL_MISSING = "approval_missing"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_REVOKED = "approval_revoked"
    APPROVAL_CONSUMED = "approval_consumed"
    RETRY_LIMIT_EXCEEDED = "retry_limit_exceeded"
    COOLDOWN_NOT_ELAPSED = "cooldown_not_elapsed"
    EVIDENCE_MISSING = "evidence_missing"
    VERIFICATION_MISSING = "verification_missing"
    ROLLBACK_MISSING = "rollback_missing"
    REQUEST_EXPIRED = "request_expired"
    REQUEST_CONSUMED = "request_consumed"
    SIMULATION_REQUIRED = "simulation_required"
    PRODUCTION_UNAVAILABLE = "production_unavailable"
    POLICY_REFERENCE_MISMATCH = "policy_reference_mismatch"


class RepairPreconditionType(str, Enum):
    FINDING_STILL_PRESENT = "finding_still_present"
    TARGET_IDENTITY_MATCHES = "target_identity_matches"
    TARGET_IS_ALLOWLISTED = "target_is_allowlisted"
    ACTION_IS_ALLOWLISTED = "action_is_allowlisted"
    BACKUP_AVAILABLE = "backup_available"
    KNOWN_GOOD_SOURCE_AVAILABLE = "known_good_source_available"
    ROLLBACK_AVAILABLE = "rollback_available"
    RETRY_BUDGET_AVAILABLE = "retry_budget_available"
    COOLDOWN_ELAPSED = "cooldown_elapsed"
    APPROVAL_VALID = "approval_valid"
    VERIFICATION_CONFIGURED = "verification_configured"
    SIMULATION_ONLY = "simulation_only"


class SimulatedRepairOutcome(str, Enum):
    AUTHORIZED_AND_SIMULATED_SUCCESS = "authorized_and_simulated_success"
    AUTHORIZED_AND_SIMULATED_FAILURE = "authorized_and_simulated_failure"
    DENIED_BY_POLICY = "denied_by_policy"
    DENIED_MISSING_ALLOWLIST = "denied_missing_allowlist"
    DENIED_MISSING_APPROVAL = "denied_missing_approval"
    DENIED_EXPIRED_APPROVAL = "denied_expired_approval"
    DENIED_RISK_TOO_HIGH = "denied_risk_too_high"
    DENIED_RETRY_LIMIT = "denied_retry_limit"
    DENIED_COOLDOWN = "denied_cooldown"
    DENIED_MISSING_VERIFICATION = "denied_missing_verification"
    DENIED_MISSING_ROLLBACK = "denied_missing_rollback"
    SIMULATED_VERIFICATION_SUCCESS = "simulated_verification_success"
    SIMULATED_VERIFICATION_FAILURE = "simulated_verification_failure"
    SIMULATED_ROLLBACK_SUCCESS = "simulated_rollback_success"
    SIMULATED_ROLLBACK_FAILURE = "simulated_rollback_failure"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"


class NotificationChannelType(str, Enum):
    TELEGRAM = "telegram"
    EMAIL = "email"
    SMS = "sms"
    WEBHOOK = "webhook"
    LOCAL_FILE = "local_file"


class CodeRepairStage(str, Enum):
    FAILURE_REPRODUCED = "failure_reproduced"
    EVIDENCE_RECORDED = "evidence_recorded"
    REPOSITORY_APPROVED = "repository_approved"
    VERSION_PRESERVED = "version_preserved"
    WORKSPACE_ISOLATED = "workspace_isolated"
    PATCH_PROPOSED = "patch_proposed"
    DIFF_PRODUCED = "diff_produced"
    TESTS_PASSED = "tests_passed"
    LINTERS_PASSED = "linters_passed"
    TYPE_CHECKS_PASSED = "type_checks_passed"
    SECURITY_CHECKS_PASSED = "security_checks_passed"
    APPROVAL_GRANTED = "approval_granted"
    DEPLOYED = "deployed"
    HEALTH_VERIFIED = "health_verified"
    ROLLED_BACK = "rolled_back"
    RESULT_REPORTED = "result_reported"


class PluginCapability(str, Enum):
    OBSERVE = "observe"
    VALIDATE = "validate"
    PROPOSE_ACTION = "propose_action"


@dataclass(frozen=True)
class GlobalSettings:
    schema_version: str
    installation_name: str
    application_name: str
    environment: str
    dry_run: bool
    poll_interval_seconds: int
    incident_directory: str
    log_level: str
    default_policy_mode: PolicyMode
    default_retry_limit: int
    default_cooldown_seconds: int
    default_verification_delay_seconds: int


@dataclass(frozen=True)
class RepairPolicy:
    id: str
    mode: PolicyMode
    allowed_actions: tuple[RepairActionCategory, ...] = ()
    allowed_target_ids: tuple[str, ...] = ()
    allowed_adapter_types: tuple[AdapterType, ...] = ()
    allowed_target_actions: tuple[tuple[str, RepairActionCategory], ...] = ()
    maximum_risk: ActionRisk = ActionRisk.INFORMATIONAL
    allowed_finding_categories: tuple[str, ...] = ()
    minimum_severity: Severity = Severity.INFO
    maximum_severity: Severity = Severity.CRITICAL
    minimum_confidence: Confidence = Confidence.LOW
    retry_limit: int | None = None
    cooldown_seconds: int | None = None
    verification_delay_seconds: int | None = None
    require_pre_repair_evidence: bool = True
    require_verification: bool = True
    rollback_on_verification_failure: bool = True


@dataclass(frozen=True)
class RepairRequest:
    request_id: str
    incident_id: str
    target_id: str
    adapter_type: AdapterType
    finding_category: ReliabilityCategory | SecurityCategory
    finding_severity: Severity
    finding_confidence: Confidence
    requested_action: RepairActionCategory
    requested_at: str
    expires_at: str
    policy_reference: str
    evidence_reference: str | None
    simulation: bool
    consumed_at: str | None = None


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    request_id: str
    approver_reference: str
    decision: ApprovalDecision
    approved_action: RepairActionCategory
    issued_at: str
    expires_at: str
    target_scope: tuple[str, ...]
    one_time: bool
    reason: str
    consumed_at: str | None = None
    revoked: bool = False


@dataclass(frozen=True)
class RetryState:
    attempts: int
    limit: int


@dataclass(frozen=True)
class CooldownState:
    last_attempt_at: str | None
    cooldown_seconds: int
    elapsed: bool


@dataclass(frozen=True)
class RepairPrecondition:
    condition: RepairPreconditionType
    satisfied: bool
    explanation: str


@dataclass(frozen=True)
class VerificationPlan:
    verification_id: str
    target_id: str
    adapter_type: AdapterType
    checks_to_repeat: tuple[str, ...]
    expected_status: str
    delay_seconds: int
    maximum_attempts: int
    success_criteria: tuple[str, ...]
    failure_criteria: tuple[str, ...]
    rollback_trigger: str | None
    manual_review_trigger: str | None


@dataclass(frozen=True)
class RollbackPlan:
    rollback_id: str
    original_action: RepairActionCategory
    rollback_action: str
    required_backup_reference: str | None
    known_good_reference: str | None
    preconditions: tuple[str, ...]
    verification_after_rollback: tuple[str, ...]
    maximum_attempts: int
    manual_intervention_fallback: str


@dataclass(frozen=True)
class AuthorizationReason:
    code: AuthorizationReasonCode
    explanation: str


@dataclass(frozen=True)
class AuthorizationDecision:
    decision_id: str
    request_id: str
    target_id: str
    action: RepairActionCategory
    risk: ActionRisk
    permitted: bool
    simulation_permitted: bool
    recommendation_only: bool
    reasons: tuple[AuthorizationReason, ...]
    approval_reference: str | None
    decided_at: str

    def to_safe_dict(self) -> dict[str, Any]:
        from .redaction import redact

        return redact(to_primitive(self))


@dataclass(frozen=True)
class RepairStep:
    step_id: str
    action: str
    description: str
    simulation_only: bool = True


@dataclass(frozen=True)
class RepairPlan:
    plan_id: str
    request: RepairRequest
    authorization: AuthorizationDecision
    risk: ActionRisk
    created_at: str
    expires_at: str
    preconditions: tuple[RepairPrecondition, ...]
    steps: tuple[RepairStep, ...]
    verification_plan: VerificationPlan
    rollback_plan: RollbackPlan | None
    approval_required: bool
    simulation: bool = True
    production_execution_available: bool = False


@dataclass(frozen=True)
class RepairAuthorizationContext:
    target: Target | None
    policy: RepairPolicy
    approval: ApprovalRecord | None
    retry_state: RetryState
    cooldown_state: CooldownState
    verification_plan: VerificationPlan | None
    rollback_plan: RollbackPlan | None
    evidence_present: bool
    finding_still_present: bool
    now: str
    production_execution_available: bool = False


@dataclass(frozen=True)
class RepairAuditEvent:
    event_id: str
    request_id: str
    incident_id: str
    target_id: str
    timestamp: str
    event_type: str
    authorization_outcome: str
    reason_codes: tuple[AuthorizationReasonCode, ...]
    policy_reference: str
    action: RepairActionCategory
    risk: ActionRisk
    simulation: bool
    approval_reference: str | None
    verification_outcome: str | None
    rollback_outcome: str | None
    final_outcome: SimulatedRepairOutcome

    def to_safe_dict(self) -> dict[str, Any]:
        from .redaction import redact

        value = redact(to_primitive(self))
        value["authorization_outcome"] = self.authorization_outcome
        return value


@dataclass(frozen=True)
class RepairAttemptRecord:
    attempt_id: str
    request_id: str
    plan_id: str
    target_id: str
    action: RepairActionCategory
    risk: ActionRisk
    started_at: str
    completed_at: str
    simulation: bool
    steps: tuple[RepairStep, ...]
    verification_outcome: str
    rollback_outcome: str
    final_outcome: SimulatedRepairOutcome


@dataclass(frozen=True)
class SimulatedRepairResult:
    request_id: str
    plan_id: str
    authorized: bool
    simulation: bool
    production_execution_available: bool
    outcome: SimulatedRepairOutcome
    steps: tuple[RepairStep, ...]
    verification_outcome: str
    rollback_outcome: str
    manual_intervention_required: bool
    attempt_record: RepairAttemptRecord
    audit_events: tuple[RepairAuditEvent, ...]


@dataclass(frozen=True)
class NotificationChannel:
    id: str
    channel_type: NotificationChannelType
    enabled: bool
    severities: tuple[Severity, ...]
    retry_limit: int
    settings: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NotificationPolicy:
    id: str
    channels: tuple[str, ...]


@dataclass(frozen=True)
class Target:
    id: str
    display_name: str
    adapter_type: AdapterType
    enabled: bool
    severity: Severity
    monitoring: dict[str, Any]
    repair_policy: str
    notification_policy: str | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class ShieldMendAiConfig:
    global_settings: GlobalSettings
    repair_policies: tuple[RepairPolicy, ...]
    notification_channels: tuple[NotificationChannel, ...]
    notification_policies: tuple[NotificationPolicy, ...]
    targets: tuple[Target, ...]


@dataclass(frozen=True)
class PlannedTarget:
    id: str
    display_name: str
    adapter_type: AdapterType
    policy_mode: PolicyMode
    notification_channel_types: tuple[NotificationChannelType, ...]


@dataclass(frozen=True)
class DryRunPlan:
    installation_name: str
    application_name: str
    dry_run: bool
    planning_only: bool
    targets: tuple[PlannedTarget, ...]


@dataclass(frozen=True)
class AdapterCapabilities:
    adapter_type: AdapterType
    supported_checks: tuple[str, ...]
    platform_requirements: tuple[str, ...] = ()
    requires_network: bool = False
    requires_subprocess: bool = False
    requires_privileged_access: bool = False
    supports_simulation: bool = True
    production_available: bool = False
    adapter_version: str = "1.0"


@dataclass(frozen=True)
class ObservationRequest:
    target: Target
    scenario_state: str
    scenario_data: dict[str, Any]


@dataclass(frozen=True)
class ObservationContext:
    observed_at: str
    fixture_root: str | None = None
    simulation: bool = True


@dataclass(frozen=True)
class FindingEvidence:
    values: dict[str, Any] = field(default_factory=dict)

    def to_safe_dict(self) -> dict[str, Any]:
        from .redaction import redact

        return redact(self.values)


@dataclass(frozen=True)
class Finding:
    target_id: str
    adapter_type: AdapterType
    observed_at: str
    status: ObservationStatus
    severity: Severity
    category: ReliabilityCategory | SecurityCategory | None
    confidence: Confidence
    summary: str
    sanitized_evidence: FindingEvidence
    expected_state: Any
    observed_state: Any
    duration_ms: int
    error_classification: ErrorClassification = ErrorClassification.NONE
    retry_recommended: bool = False
    manual_review_required: bool = False
    simulation: bool = True
    adapter_version: str = "1.0"

    def to_safe_dict(self) -> dict[str, Any]:
        from .redaction import redact

        value = to_primitive(self)
        value["sanitized_evidence"] = self.sanitized_evidence.to_safe_dict()
        return redact(value)


@dataclass(frozen=True)
class ObservationResult:
    target_id: str
    adapter_type: AdapterType
    status: ObservationStatus
    findings: tuple[Finding, ...]
    duration_ms: int
    simulation: bool
    adapter_version: str


@dataclass(frozen=True)
class IncidentAction:
    category: RepairActionCategory
    status: LifecycleStatus
    summary: str
    attempted_at: str | None = None


@dataclass(frozen=True)
class NotificationAttempt:
    channel_type: NotificationChannelType
    attempted: bool
    delivered: bool | None
    sanitized_error: str | None = None


@dataclass(frozen=True)
class PluginRequest:
    schema_version: str
    request_id: str
    capability: PluginCapability
    target_id: str
    sanitized_parameters: dict[str, Any]
    timeout_seconds: int


@dataclass(frozen=True)
class PluginResponse:
    schema_version: str
    request_id: str
    success: bool
    sanitized_result: dict[str, Any]
    sanitized_error: str | None = None


@dataclass(frozen=True)
class CodeRepairWorkflow:
    repository_reference: str
    approved_branch: str
    preserved_commit: str
    deployment_version: str
    current_stage: CodeRepairStage
    required_checks: tuple[str, ...]
    customer_approval_required: bool = True
    rollback_required_on_failed_verification: bool = True


@dataclass(frozen=True)
class Incident:
    incident_id: str
    schema_version: str
    application_id: str
    target_id: str
    created_at: str
    updated_at: str
    severity: Severity
    category: ReliabilityCategory | SecurityCategory
    detection_source: str
    sanitized_evidence: dict[str, Any]
    diagnosis_status: LifecycleStatus
    proposed_action: RepairActionCategory
    policy_mode: PolicyMode
    approval_status: ApprovalStatus
    actions_attempted: tuple[IncidentAction, ...] = ()
    verification_result: VerificationResult = VerificationResult.NOT_RUN
    rollback_status: RollbackStatus = RollbackStatus.NOT_REQUIRED
    final_outcome: LifecycleStatus = LifecycleStatus.SUSPECTED
    notifications_attempted: tuple[NotificationAttempt, ...] = ()
    notification_delivery_results: dict[str, str] = field(default_factory=dict)
    manual_intervention_required: bool = False

    def to_safe_dict(self) -> dict[str, Any]:
        """Serialize through the mandatory redaction boundary."""
        from .redaction import redact

        return redact(to_primitive(self))

    @classmethod
    def planning_record(
        cls,
        incident_id: str,
        application_id: str,
        target_id: str,
        category: ReliabilityCategory | SecurityCategory,
        severity: Severity,
    ) -> "Incident":
        now = datetime.now(timezone.utc).isoformat()
        return cls(
            incident_id=incident_id,
            schema_version="1.0",
            application_id=application_id,
            target_id=target_id,
            created_at=now,
            updated_at=now,
            severity=severity,
            category=category,
            detection_source="planning_only",
            sanitized_evidence={},
            diagnosis_status=LifecycleStatus.SUSPECTED,
            proposed_action=RepairActionCategory.NO_ACTION,
            policy_mode=PolicyMode.OBSERVE_ONLY,
            approval_status=ApprovalStatus.NOT_REQUIRED,
        )


def to_primitive(value: Any) -> Any:
    """Convert typed models and enums to JSON/YAML-safe primitives."""
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return to_primitive(asdict(value))
    if isinstance(value, dict):
        return {str(key): to_primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_primitive(item) for item in value]
    return value
