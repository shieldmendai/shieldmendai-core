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
    retry_limit: int | None = None
    cooldown_seconds: int | None = None
    verification_delay_seconds: int | None = None
    require_pre_repair_evidence: bool = True
    require_verification: bool = True
    rollback_on_verification_failure: bool = True


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
