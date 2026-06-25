"""Sanitized incident records, fixture-confined storage, and retention simulation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar

import yaml

from .errors import IncidentTransitionError, IncidentValidationError, UnsafeIncidentStoreError
from .models import AdapterType, Confidence, ReliabilityCategory, SecurityCategory, Severity
from .redaction import redact, sanitize_message

SCHEMA_VERSION = "1.0"
MAX_RETENTION_DAYS = 36_500
MAX_RECORDS = 1_000_000
MAX_BYTES = 1_000_000_000_000
_T = TypeVar("_T")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
_SENSITIVE_KEY = re.compile(
    r"(token|password|secret|credential|api[_-]?key|private[_-]?key|seed|wallet|"
    r"authorization|cookie|environment|source[_-]?file|full[_-]?log)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:token|password|api[_-]?key|secret)\s*[:=]|"
    r"[a-z][a-z0-9+.-]*://[^/\s]+@)",
    re.IGNORECASE,
)
_FORBIDDEN_PRIVATE = "/root/" + "newbasebot"
_FORBIDDEN_PREFIX = "new" + "base-"
_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class IncidentStatus(str, Enum):
    DETECTED = "detected"
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    REMEDIATION_PLANNED = "remediation_planned"
    SIMULATED_RECOVERY_RUNNING = "simulated_recovery_running"
    MONITORING_VERIFICATION = "monitoring_verification"
    RESOLVED = "resolved"
    CLOSED = "closed"
    SUPPRESSED = "suppressed"
    DUPLICATE = "duplicate"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"


class IncidentEventType(str, Enum):
    INCIDENT_CREATED = "incident_created"
    FINDING_RECORDED = "finding_recorded"
    SEVERITY_CHANGED = "severity_changed"
    STATUS_CHANGED = "status_changed"
    INCIDENT_ACKNOWLEDGED = "incident_acknowledged"
    REMEDIATION_RECOMMENDED = "remediation_recommended"
    REPAIR_AUTHORIZED = "repair_authorized"
    REPAIR_DENIED = "repair_denied"
    SIMULATED_REPAIR_STARTED = "simulated_repair_started"
    SIMULATED_REPAIR_COMPLETED = "simulated_repair_completed"
    VERIFICATION_STARTED = "verification_started"
    VERIFICATION_SUCCEEDED = "verification_succeeded"
    VERIFICATION_FAILED = "verification_failed"
    ROLLBACK_REQUIRED = "rollback_required"
    ROLLBACK_COMPLETED = "rollback_completed"
    ROLLBACK_FAILED = "rollback_failed"
    CIRCUIT_OPENED = "circuit_opened"
    MANUAL_INTERVENTION_REQUESTED = "manual_intervention_requested"
    NOTIFICATION_PLANNED = "notification_planned"
    NOTIFICATION_SUPPRESSED = "notification_suppressed"
    NOTIFICATION_SIMULATED = "notification_simulated"
    INCIDENT_RESOLVED = "incident_resolved"
    INCIDENT_CLOSED = "incident_closed"
    INCIDENT_MARKED_DUPLICATE = "incident_marked_duplicate"
    RETENTION_PREVIEWED = "retention_previewed"
    RETENTION_SIMULATED = "retention_simulated"


class IncidentSource(str, Enum):
    OBSERVATION = "observation"
    REPAIR = "repair"
    RECOVERY = "recovery"
    MANUAL = "manual"
    SIMULATION = "simulation"


class IncidentOutcome(str, Enum):
    PENDING = "pending"
    RESOLVED = "resolved"
    CLOSED = "closed"
    SUPPRESSED = "suppressed"
    DUPLICATE = "duplicate"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"


class RetentionDecision(str, Enum):
    RETAIN = "retain"
    ELIGIBLE_FOR_REMOVAL = "eligible_for_removal"
    PROTECTED_UNRESOLVED = "protected_unresolved"
    PROTECTED_MANUAL_INTERVENTION = "protected_manual_intervention"
    PROTECTED_SEVERITY = "protected_severity"
    PROTECTED_LATEST_VERSION = "protected_latest_version"
    PROTECTED_POLICY = "protected_policy"
    INVALID_RECORD = "invalid_record"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


VALID_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.DETECTED: frozenset(
        {IncidentStatus.OPEN, IncidentStatus.SUPPRESSED, IncidentStatus.DUPLICATE}
    ),
    IncidentStatus.OPEN: frozenset(
        {
            IncidentStatus.ACKNOWLEDGED,
            IncidentStatus.INVESTIGATING,
            IncidentStatus.REMEDIATION_PLANNED,
            IncidentStatus.RESOLVED,
            IncidentStatus.SUPPRESSED,
            IncidentStatus.DUPLICATE,
            IncidentStatus.MANUAL_INTERVENTION_REQUIRED,
        }
    ),
    IncidentStatus.ACKNOWLEDGED: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.REMEDIATION_PLANNED,
            IncidentStatus.RESOLVED,
            IncidentStatus.MANUAL_INTERVENTION_REQUIRED,
        }
    ),
    IncidentStatus.INVESTIGATING: frozenset(
        {
            IncidentStatus.REMEDIATION_PLANNED,
            IncidentStatus.SIMULATED_RECOVERY_RUNNING,
            IncidentStatus.MONITORING_VERIFICATION,
            IncidentStatus.RESOLVED,
            IncidentStatus.MANUAL_INTERVENTION_REQUIRED,
        }
    ),
    IncidentStatus.REMEDIATION_PLANNED: frozenset(
        {
            IncidentStatus.SIMULATED_RECOVERY_RUNNING,
            IncidentStatus.MONITORING_VERIFICATION,
            IncidentStatus.RESOLVED,
            IncidentStatus.MANUAL_INTERVENTION_REQUIRED,
        }
    ),
    IncidentStatus.SIMULATED_RECOVERY_RUNNING: frozenset(
        {
            IncidentStatus.MONITORING_VERIFICATION,
            IncidentStatus.RESOLVED,
            IncidentStatus.MANUAL_INTERVENTION_REQUIRED,
        }
    ),
    IncidentStatus.MONITORING_VERIFICATION: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.RESOLVED,
            IncidentStatus.MANUAL_INTERVENTION_REQUIRED,
        }
    ),
    IncidentStatus.RESOLVED: frozenset({IncidentStatus.CLOSED, IncidentStatus.OPEN}),
    IncidentStatus.CLOSED: frozenset(),
    IncidentStatus.SUPPRESSED: frozenset(),
    IncidentStatus.DUPLICATE: frozenset(),
    IncidentStatus.MANUAL_INTERVENTION_REQUIRED: frozenset(
        {IncidentStatus.INVESTIGATING, IncidentStatus.REMEDIATION_PLANNED}
    ),
}


@dataclass(frozen=True)
class IncidentEvidenceReference:
    reference_id: str
    evidence_type: str
    summary: str
    source_reference: str | None = None
    redacted: bool = True


@dataclass(frozen=True)
class IncidentTargetReference:
    application_id: str
    target_id: str
    adapter_type: AdapterType


@dataclass(frozen=True)
class IncidentCorrelationReference:
    correlation_id: str
    fingerprint: str
    canonical_incident_id: str | None
    window_seconds: int
    duplicate: bool


@dataclass(frozen=True)
class IncidentEvent:
    event_id: str
    incident_id: str
    timestamp: str
    event_type: IncidentEventType
    prior_status: IncidentStatus | None
    new_status: IncidentStatus
    severity: Severity
    category: str
    source: IncidentSource
    reason_code: str
    sanitized_message: str
    observation_reference: str | None = None
    repair_reference: str | None = None
    recovery_reference: str | None = None
    notification_reference: str | None = None
    correlation_reference: str | None = None
    simulation: bool = True


@dataclass(frozen=True)
class IncidentSummary:
    incident_id: str
    status: IncidentStatus
    severity: Severity
    category: str
    summary: str
    event_count: int
    manual_intervention_required: bool
    final_outcome: IncidentOutcome
    simulation: bool


@dataclass(frozen=True)
class IncidentStoreMetadata:
    schema_version: str
    record_version: int
    record_id: str
    previous_record_version: int | None
    created_at: str
    updated_at: str
    checksum: str


@dataclass(frozen=True)
class IncidentRecord:
    metadata: IncidentStoreMetadata
    incident_id: str
    application_id: str
    target_id: str
    adapter_type: AdapterType
    category: str
    severity: Severity
    confidence: Confidence
    status: IncidentStatus
    summary: str
    sanitized_description: str
    created_at: str
    updated_at: str
    detected_at: str
    acknowledged_at: str | None
    resolved_at: str | None
    closed_at: str | None
    source: IncidentSource
    policy_reference: str | None
    repair_request_reference: str | None
    recovery_controller_reference: str | None
    current_recovery_state: str | None
    final_outcome: IncidentOutcome
    manual_intervention_required: bool
    evidence_references: tuple[IncidentEvidenceReference, ...]
    events: tuple[IncidentEvent, ...]
    notification_summary: dict[str, Any]
    correlation: IncidentCorrelationReference | None
    suppression_reason_code: str | None
    simulation: bool
    tags: tuple[str, ...]

    def to_safe_dict(self) -> dict[str, Any]:
        return _primitive(self)

    def summarized(self) -> IncidentSummary:
        return IncidentSummary(
            self.incident_id,
            self.status,
            self.severity,
            self.category,
            self.summary,
            len(self.events),
            self.manual_intervention_required,
            self.final_outcome,
            self.simulation,
        )


@dataclass(frozen=True)
class RetentionPolicy:
    schema_version: str
    retention_policy_id: str
    enabled: bool
    maximum_age_days: int | None
    maximum_record_count: int | None
    maximum_total_bytes: int | None
    retain_minimum_severity: Severity | None
    retain_unresolved: bool
    retain_manual_intervention: bool
    retain_latest_versions: bool
    archive_before_delete: bool
    dry_run: bool
    review_required: bool


@dataclass(frozen=True)
class RetentionCandidate:
    incident_id: str
    record_id: str
    record_version: int
    decision: RetentionDecision
    reason: str
    path: str
    size_bytes: int
    simulation: bool = True


@dataclass(frozen=True)
class RetentionPreview:
    policy_id: str
    evaluated_at: str
    candidates: tuple[RetentionCandidate, ...]
    retained_count: int
    eligible_count: int
    modified: bool = False
    simulation: bool = True


@dataclass(frozen=True)
class RetentionSimulationResult:
    preview: RetentionPreview
    removed_fixture_records: tuple[str, ...]
    audit_events: tuple[dict[str, Any], ...]
    production_records_affected: bool = False
    simulation: bool = True


@dataclass(frozen=True)
class RetentionSimulationScenario:
    schema_version: str
    scenario_id: str
    now: str
    remove_generated_fixtures: bool
    simulation: bool = True


def _primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return _primitive(asdict(value))
    if isinstance(value, dict):
        return {str(key): _primitive(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_primitive(item) for item in value]
    return value


def _mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IncidentValidationError(f"{location} must be a mapping")
    return value


def _list(value: Any, location: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise IncidentValidationError(f"{location} must be a list")
    return value


def _text(
    value: Any,
    location: str,
    *,
    identifier: bool = False,
    reference: bool = False,
    maximum: int = 1000,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IncidentValidationError(f"{location} must be a non-empty string")
    result = sanitize_message(value.strip())
    if "<redacted>" in result.lower():
        result = "[REDACTED]"
    if len(result) > maximum:
        raise IncidentValidationError(f"{location} is too long")
    if _FORBIDDEN_PRIVATE in result or _FORBIDDEN_PREFIX in result:
        raise IncidentValidationError(f"{location} contains a prohibited private reference")
    if _SENSITIVE_VALUE.search(result):
        raise IncidentValidationError(f"{location} contains credential-like data")
    if identifier and not _ID.fullmatch(result):
        raise IncidentValidationError(f"{location} contains unsupported characters")
    if reference and not _REFERENCE.fullmatch(result):
        raise IncidentValidationError(f"{location} must be a sanitized reference")
    return result


def _optional_text(
    value: Any, location: str, *, reference: bool = False, maximum: int = 1000
) -> str | None:
    if value is None:
        return None
    return _text(value, location, reference=reference, maximum=maximum)


def _boolean(value: Any, location: str) -> bool:
    if not isinstance(value, bool):
        raise IncidentValidationError(f"{location} must be true or false")
    return value


def _integer(value: Any, location: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise IncidentValidationError(
            f"{location} must be an integer between {minimum} and {maximum}"
        )
    return value


def _enum(enum_type: type[_T], value: Any, location: str) -> _T:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        raise IncidentValidationError(f"{location} is unknown") from None


def _timestamp(value: Any, location: str) -> str:
    text = _text(value, location, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise IncidentValidationError(f"{location} must be an ISO-8601 timestamp") from None
    if parsed.tzinfo is None:
        raise IncidentValidationError(f"{location} must include a timezone")
    return text


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _reject_sensitive(value: Any, location: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _SENSITIVE_KEY.search(str(key)) and item not in (None, "", [], {}):
                raise IncidentValidationError(f"{location}.{key} is prohibited")
            _reject_sensitive(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_sensitive(item, f"{location}[{index}]")
    elif isinstance(value, str) and (
        _SENSITIVE_VALUE.search(value)
        or _FORBIDDEN_PRIVATE in value
        or _FORBIDDEN_PREFIX in value
    ):
        raise IncidentValidationError(f"{location} contains prohibited data")


def _canonical_content(data: dict[str, Any]) -> bytes:
    value = json.loads(json.dumps(data))
    value["metadata"]["checksum"] = ""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def incident_checksum(data: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_content(data)).hexdigest()


def _event(data: Any, incident_id: str, index: int) -> IncidentEvent:
    item = _mapping(data, f"events[{index}]")
    event_incident = _text(item.get("incident_id"), f"events[{index}].incident_id", identifier=True)
    if event_incident != incident_id:
        raise IncidentValidationError("event incident ID does not match record")
    return IncidentEvent(
        event_id=_text(item.get("event_id"), f"events[{index}].event_id", identifier=True),
        incident_id=event_incident,
        timestamp=_timestamp(item.get("timestamp"), f"events[{index}].timestamp"),
        event_type=_enum(
            IncidentEventType, item.get("event_type"), f"events[{index}].event_type"
        ),
        prior_status=(
            _enum(IncidentStatus, item.get("prior_status"), f"events[{index}].prior_status")
            if item.get("prior_status") is not None
            else None
        ),
        new_status=_enum(
            IncidentStatus, item.get("new_status"), f"events[{index}].new_status"
        ),
        severity=_enum(Severity, item.get("severity"), f"events[{index}].severity"),
        category=_text(item.get("category"), f"events[{index}].category", identifier=True),
        source=_enum(IncidentSource, item.get("source"), f"events[{index}].source"),
        reason_code=_text(
            item.get("reason_code"), f"events[{index}].reason_code", identifier=True
        ),
        sanitized_message=_text(
            item.get("sanitized_message"), f"events[{index}].sanitized_message"
        ),
        observation_reference=_optional_text(
            item.get("observation_reference"),
            f"events[{index}].observation_reference",
            reference=True,
        ),
        repair_reference=_optional_text(
            item.get("repair_reference"), f"events[{index}].repair_reference", reference=True
        ),
        recovery_reference=_optional_text(
            item.get("recovery_reference"),
            f"events[{index}].recovery_reference",
            reference=True,
        ),
        notification_reference=_optional_text(
            item.get("notification_reference"),
            f"events[{index}].notification_reference",
            reference=True,
        ),
        correlation_reference=_optional_text(
            item.get("correlation_reference"),
            f"events[{index}].correlation_reference",
            reference=True,
        ),
        simulation=_boolean(item.get("simulation"), f"events[{index}].simulation"),
    )


def parse_incident_record(data: Any, *, verify_checksum: bool = True) -> IncidentRecord:
    root = _mapping(data, "incident")
    _reject_sensitive(root, "incident")
    metadata = _mapping(root.get("metadata"), "metadata")
    if metadata.get("schema_version") != SCHEMA_VERSION:
        raise IncidentValidationError("unsupported incident schema version")
    record_version = _integer(metadata.get("record_version"), "metadata.record_version", 1, MAX_RECORDS)
    previous = metadata.get("previous_record_version")
    if previous is not None:
        previous = _integer(previous, "metadata.previous_record_version", 1, MAX_RECORDS)
        if previous >= record_version:
            raise IncidentValidationError("record version rollback or invalid predecessor")
    checksum = _text(metadata.get("checksum"), "metadata.checksum", maximum=64)
    if not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise IncidentValidationError("incident checksum is malformed")
    if verify_checksum and checksum != incident_checksum(root):
        raise IncidentValidationError("incident checksum does not match sanitized content")
    incident_id = _text(root.get("incident_id"), "incident_id", identifier=True)
    events = tuple(
        _event(item, incident_id, index)
        for index, item in enumerate(_list(root.get("events"), "events"))
    )
    event_ids = [item.event_id for item in events]
    if len(event_ids) != len(set(event_ids)):
        raise IncidentValidationError("duplicate incident event ID")
    if list(events) != sorted(events, key=lambda item: _time(item.timestamp)):
        raise IncidentValidationError("incident events must be chronologically ordered")
    if events:
        if (
            events[0].prior_status is not None
            or events[0].new_status is not IncidentStatus.DETECTED
            or events[0].event_type is not IncidentEventType.INCIDENT_CREATED
        ):
            raise IncidentValidationError("incident timeline must start with creation")
        previous_status = events[0].new_status
        for item in events[1:]:
            if (
                item.prior_status is not previous_status
                or item.new_status
                not in VALID_TRANSITIONS.get(previous_status, frozenset())
            ):
                raise IncidentValidationError(
                    "incident timeline contains an invalid transition"
                )
            previous_status = item.new_status
    evidence: list[IncidentEvidenceReference] = []
    for index, raw in enumerate(_list(root.get("evidence_references"), "evidence_references")):
        item = _mapping(raw, f"evidence_references[{index}]")
        evidence.append(
            IncidentEvidenceReference(
                _text(item.get("reference_id"), f"evidence_references[{index}].reference_id", identifier=True),
                _text(item.get("evidence_type"), f"evidence_references[{index}].evidence_type", identifier=True),
                _text(item.get("summary"), f"evidence_references[{index}].summary"),
                _optional_text(
                    item.get("source_reference"),
                    f"evidence_references[{index}].source_reference",
                    reference=True,
                ),
                _boolean(item.get("redacted", True), f"evidence_references[{index}].redacted"),
            )
        )
    correlation = None
    if root.get("correlation") is not None:
        item = _mapping(root["correlation"], "correlation")
        correlation = IncidentCorrelationReference(
            _text(item.get("correlation_id"), "correlation.correlation_id", identifier=True),
            _text(item.get("fingerprint"), "correlation.fingerprint", maximum=64),
            _optional_text(
                item.get("canonical_incident_id"),
                "correlation.canonical_incident_id",
                reference=True,
            ),
            _integer(item.get("window_seconds"), "correlation.window_seconds", 0, 31_536_000),
            _boolean(item.get("duplicate"), "correlation.duplicate"),
        )
        if correlation.duplicate and not correlation.canonical_incident_id:
            raise IncidentValidationError("duplicate incident requires canonical incident reference")
    status = _enum(IncidentStatus, root.get("status"), "status")
    suppression = _optional_text(
        root.get("suppression_reason_code"), "suppression_reason_code", reference=True
    )
    if status is IncidentStatus.SUPPRESSED and not suppression:
        raise IncidentValidationError("suppressed incident requires a reason code")
    if status is IncidentStatus.DUPLICATE and not (correlation and correlation.duplicate):
        raise IncidentValidationError("duplicate incident requires correlation metadata")
    manual = _boolean(
        root.get("manual_intervention_required"), "manual_intervention_required"
    )
    if status is IncidentStatus.MANUAL_INTERVENTION_REQUIRED and not manual:
        raise IncidentValidationError("manual-intervention status requires its flag")
    record = IncidentRecord(
        IncidentStoreMetadata(
            SCHEMA_VERSION,
            record_version,
            _text(metadata.get("record_id"), "metadata.record_id", identifier=True),
            previous,
            _timestamp(metadata.get("created_at"), "metadata.created_at"),
            _timestamp(metadata.get("updated_at"), "metadata.updated_at"),
            checksum,
        ),
        incident_id,
        _text(root.get("application_id"), "application_id", identifier=True),
        _text(root.get("target_id"), "target_id", identifier=True),
        _enum(AdapterType, root.get("adapter_type"), "adapter_type"),
        _text(root.get("category"), "category", identifier=True),
        _enum(Severity, root.get("severity"), "severity"),
        _enum(Confidence, root.get("confidence"), "confidence"),
        status,
        _text(root.get("summary"), "summary", maximum=240),
        _text(root.get("sanitized_description"), "sanitized_description", maximum=2000),
        _timestamp(root.get("created_at"), "created_at"),
        _timestamp(root.get("updated_at"), "updated_at"),
        _timestamp(root.get("detected_at"), "detected_at"),
        _optional_timestamp(root.get("acknowledged_at"), "acknowledged_at"),
        _optional_timestamp(root.get("resolved_at"), "resolved_at"),
        _optional_timestamp(root.get("closed_at"), "closed_at"),
        _enum(IncidentSource, root.get("source"), "source"),
        _optional_text(root.get("policy_reference"), "policy_reference", reference=True),
        _optional_text(
            root.get("repair_request_reference"),
            "repair_request_reference",
            reference=True,
        ),
        _optional_text(
            root.get("recovery_controller_reference"),
            "recovery_controller_reference",
            reference=True,
        ),
        _optional_text(
            root.get("current_recovery_state"),
            "current_recovery_state",
            reference=True,
        ),
        _enum(IncidentOutcome, root.get("final_outcome"), "final_outcome"),
        manual,
        tuple(evidence),
        events,
        redact(_mapping(root.get("notification_summary", {}), "notification_summary")),
        correlation,
        suppression,
        _boolean(root.get("simulation"), "simulation"),
        tuple(
            _text(item, "tags", identifier=True)
            for item in _list(root.get("tags"), "tags")
        ),
    )
    if not record.simulation or any(not item.simulation for item in record.events):
        raise IncidentValidationError("Phase 6 incident records must be simulation-only")
    if record.events and record.events[-1].new_status is not record.status:
        raise IncidentValidationError("latest event status does not match incident status")
    return record


def _optional_timestamp(value: Any, location: str) -> str | None:
    return None if value is None else _timestamp(value, location)


def create_incident_record(
    *,
    incident_id: str,
    application_id: str,
    target_id: str,
    adapter_type: AdapterType,
    category: ReliabilityCategory | SecurityCategory | str,
    severity: Severity,
    confidence: Confidence,
    summary: str,
    sanitized_description: str,
    timestamp: str,
    source: IncidentSource = IncidentSource.SIMULATION,
    evidence_references: tuple[IncidentEvidenceReference, ...] = (),
    tags: tuple[str, ...] = (),
) -> IncidentRecord:
    now = _timestamp(timestamp, "timestamp")
    category_value = category.value if isinstance(category, Enum) else category
    event = IncidentEvent(
        f"{incident_id}.event.1",
        incident_id,
        now,
        IncidentEventType.INCIDENT_CREATED,
        None,
        IncidentStatus.DETECTED,
        severity,
        _text(category_value, "category", identifier=True),
        source,
        "incident_created",
        "Sanitized incident record created.",
    )
    metadata = IncidentStoreMetadata(
        SCHEMA_VERSION, 1, f"{incident_id}.record.1", None, now, now, ""
    )
    record = IncidentRecord(
        metadata,
        _text(incident_id, "incident_id", identifier=True),
        _text(application_id, "application_id", identifier=True),
        _text(target_id, "target_id", identifier=True),
        adapter_type,
        event.category,
        severity,
        confidence,
        IncidentStatus.DETECTED,
        _text(summary, "summary", maximum=240),
        _text(sanitized_description, "sanitized_description", maximum=2000),
        now,
        now,
        now,
        None,
        None,
        None,
        source,
        None,
        None,
        None,
        None,
        IncidentOutcome.PENDING,
        False,
        evidence_references,
        (event,),
        {},
        None,
        None,
        True,
        tuple(_text(item, "tags", identifier=True) for item in tags),
    )
    return with_checksum(record)


def with_checksum(record: IncidentRecord) -> IncidentRecord:
    clean = replace(record, metadata=replace(record.metadata, checksum=""))
    checksum = incident_checksum(clean.to_safe_dict())
    return replace(clean, metadata=replace(clean.metadata, checksum=checksum))


def transition_incident(
    record: IncidentRecord,
    new_status: IncidentStatus,
    *,
    timestamp: str,
    event_type: IncidentEventType = IncidentEventType.STATUS_CHANGED,
    reason_code: str,
    sanitized_message: str,
    canonical_incident_id: str | None = None,
    suppression_reason_code: str | None = None,
) -> IncidentRecord:
    if new_status not in VALID_TRANSITIONS.get(record.status, frozenset()):
        raise IncidentTransitionError("invalid incident lifecycle transition")
    if record.status is IncidentStatus.RESOLVED and new_status is IncidentStatus.OPEN:
        if event_type not in {
            IncidentEventType.FINDING_RECORDED,
            IncidentEventType.STATUS_CHANGED,
        }:
            raise IncidentTransitionError("resolved incident requires a new finding event to reopen")
    if record.status is IncidentStatus.CLOSED:
        raise IncidentTransitionError("closed incident cannot reopen")
    when = _timestamp(timestamp, "transition.timestamp")
    if _time(when) < _time(record.updated_at):
        raise IncidentTransitionError("transition timestamp cannot move backward")
    reason = _text(reason_code, "transition.reason_code", identifier=True)
    message = _text(sanitized_message, "transition.sanitized_message")
    correlation = record.correlation
    suppression = record.suppression_reason_code
    if new_status is IncidentStatus.DUPLICATE:
        canonical = _text(
            canonical_incident_id, "canonical_incident_id", reference=True
        )
        if canonical == record.incident_id:
            raise IncidentTransitionError("duplicate canonical incident cannot reference itself")
        correlation = IncidentCorrelationReference(
            f"{record.incident_id}.correlation",
            correlation_fingerprint(record),
            canonical,
            0,
            True,
        )
    if new_status is IncidentStatus.SUPPRESSED:
        suppression = _text(
            suppression_reason_code, "suppression_reason_code", identifier=True
        )
    event = IncidentEvent(
        f"{record.incident_id}.event.{len(record.events) + 1}",
        record.incident_id,
        when,
        event_type,
        record.status,
        new_status,
        record.severity,
        record.category,
        record.source,
        reason,
        message,
        correlation_reference=correlation.correlation_id if correlation else None,
    )
    outcome = record.final_outcome
    if new_status is IncidentStatus.RESOLVED:
        outcome = IncidentOutcome.RESOLVED
    elif new_status is IncidentStatus.CLOSED:
        outcome = IncidentOutcome.CLOSED
    elif new_status is IncidentStatus.SUPPRESSED:
        outcome = IncidentOutcome.SUPPRESSED
    elif new_status is IncidentStatus.DUPLICATE:
        outcome = IncidentOutcome.DUPLICATE
    elif new_status is IncidentStatus.MANUAL_INTERVENTION_REQUIRED:
        outcome = IncidentOutcome.MANUAL_INTERVENTION_REQUIRED
    updated = replace(
        record,
        metadata=replace(
            record.metadata,
            record_version=record.metadata.record_version + 1,
            record_id=f"{record.incident_id}.record.{record.metadata.record_version + 1}",
            previous_record_version=record.metadata.record_version,
            updated_at=when,
            checksum="",
        ),
        status=new_status,
        updated_at=when,
        acknowledged_at=(
            when if new_status is IncidentStatus.ACKNOWLEDGED else record.acknowledged_at
        ),
        resolved_at=when if new_status is IncidentStatus.RESOLVED else record.resolved_at,
        closed_at=when if new_status is IncidentStatus.CLOSED else record.closed_at,
        final_outcome=outcome,
        manual_intervention_required=(
            True
            if new_status is IncidentStatus.MANUAL_INTERVENTION_REQUIRED
            else record.manual_intervention_required
        ),
        events=record.events + (event,),
        correlation=correlation,
        suppression_reason_code=suppression,
    )
    return with_checksum(updated)


def correlation_fingerprint(record: IncidentRecord, finding_fingerprint: str = "") -> str:
    normalized = "|".join(
        (
            record.application_id,
            record.target_id,
            record.category,
            record.adapter_type.value,
            _text(finding_fingerprint or "none", "finding_fingerprint", identifier=True),
        )
    )
    return hashlib.sha256(normalized.encode()).hexdigest()


def correlate_incidents(
    candidate: IncidentRecord,
    canonical: IncidentRecord,
    *,
    finding_fingerprint: str,
    window_seconds: int,
) -> IncidentCorrelationReference:
    window = _integer(window_seconds, "window_seconds", 0, 31_536_000)
    if candidate.application_id != canonical.application_id:
        return IncidentCorrelationReference(
            f"{candidate.incident_id}.correlation",
            correlation_fingerprint(candidate, finding_fingerprint),
            None,
            window,
            False,
        )
    candidate_fp = correlation_fingerprint(candidate, finding_fingerprint)
    canonical_fp = correlation_fingerprint(canonical, finding_fingerprint)
    duplicate = (
        candidate_fp == canonical_fp
        and abs((_time(candidate.detected_at) - _time(canonical.detected_at)).total_seconds())
        <= window
    )
    return IncidentCorrelationReference(
        f"{candidate.incident_id}.correlation",
        candidate_fp,
        canonical.incident_id if duplicate else None,
        window,
        duplicate,
    )


def validate_store_root(root: str | Path) -> Path:
    candidate = Path(root)
    if not candidate.is_absolute():
        raise UnsafeIncidentStoreError("incident store root must be an explicit absolute path")
    raw = str(candidate)
    if _FORBIDDEN_PRIVATE in raw or _FORBIDDEN_PREFIX in raw or ".." in candidate.parts:
        raise UnsafeIncidentStoreError("incident store root is prohibited")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise UnsafeIncidentStoreError("incident store root must already exist") from None
    if candidate.absolute() != resolved:
        raise UnsafeIncidentStoreError("incident store root cannot traverse symlinks")
    if not resolved.is_dir() or not resolved.is_relative_to(Path(tempfile.gettempdir())):
        raise UnsafeIncidentStoreError(
            "incident store root must be an existing temporary or fixture directory"
        )
    if candidate.is_symlink():
        raise UnsafeIncidentStoreError("incident store root cannot be a symlink")
    return resolved


def _confined(root: Path, name: str) -> Path:
    if not _ID.fullmatch(name):
        raise UnsafeIncidentStoreError("incident storage name is invalid")
    path = root / f"{name}.json"
    parent = path.parent.resolve(strict=True)
    if not parent.is_relative_to(root):
        raise UnsafeIncidentStoreError("incident path escapes store root")
    if path.exists() and path.is_symlink():
        raise UnsafeIncidentStoreError("incident path cannot be a symlink")
    return path


class LocalIncidentStore:
    def __init__(self, root: str | Path) -> None:
        self.root = validate_store_root(root)

    def write(self, record: IncidentRecord) -> Path:
        validated = parse_incident_record(record.to_safe_dict())
        existing_versions: list[int] = []
        for existing_path in self.root.glob(f"{validated.incident_id}.record.*.json"):
            if existing_path.is_symlink():
                raise UnsafeIncidentStoreError("incident store contains an unsafe symlink")
            try:
                existing = parse_incident_record(
                    json.loads(existing_path.read_text(encoding="utf-8"))
                )
            except (OSError, json.JSONDecodeError):
                raise IncidentValidationError(
                    "cannot validate existing incident version"
                ) from None
            existing_versions.append(existing.metadata.record_version)
        if (
            existing_versions
            and validated.metadata.record_version <= max(existing_versions)
        ):
            raise IncidentValidationError(
                "record version rollback or duplicate version"
            )
        path = _confined(self.root, validated.metadata.record_id)
        payload = json.dumps(validated.to_safe_dict(), indent=2, sort_keys=True) + "\n"
        handle, temporary_name = tempfile.mkstemp(
            prefix=".incident-", suffix=".tmp", dir=self.root
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            temporary = Path(temporary_name)
            if temporary.is_symlink() or not temporary.resolve().is_relative_to(self.root):
                raise UnsafeIncidentStoreError("atomic incident write escaped store root")
            os.replace(temporary, path)
        finally:
            temporary = Path(temporary_name)
            if temporary.exists():
                temporary.unlink()
        return path

    def read(self, record_id: str) -> IncidentRecord:
        path = _confined(self.root, record_id)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise IncidentValidationError("cannot read valid incident record") from None
        return parse_incident_record(data)

    def list_records(self) -> tuple[IncidentRecord, ...]:
        records: list[IncidentRecord] = []
        for path in sorted(self.root.glob("*.json")):
            if path.is_symlink():
                raise UnsafeIncidentStoreError("incident store contains an unsafe symlink")
            try:
                records.append(parse_incident_record(json.loads(path.read_text(encoding="utf-8"))))
            except (OSError, json.JSONDecodeError):
                raise IncidentValidationError("incident store contains invalid JSON") from None
        return tuple(records)

    def inspect(self) -> dict[str, Any]:
        valid = 0
        invalid = 0
        total = 0
        for path in sorted(self.root.glob("*.json")):
            total += path.stat().st_size
            try:
                parse_incident_record(json.loads(path.read_text(encoding="utf-8")))
                valid += 1
            except (OSError, json.JSONDecodeError, IncidentValidationError):
                invalid += 1
        return {
            "record_count": valid + invalid,
            "valid_record_count": valid,
            "invalid_record_count": invalid,
            "total_bytes": total,
            "simulation": True,
        }


def parse_retention_policy(data: Any) -> RetentionPolicy:
    root = _mapping(data, "retention policy")
    _reject_sensitive(root, "retention policy")
    item = _mapping(root.get("policy", root), "policy")
    if item.get("schema_version", root.get("schema_version")) != SCHEMA_VERSION:
        raise IncidentValidationError("unsupported retention policy schema version")

    def optional_limit(key: str, maximum: int) -> int | None:
        value = item.get(key)
        return None if value is None else _integer(value, f"policy.{key}", 0, maximum)

    return RetentionPolicy(
        SCHEMA_VERSION,
        _text(item.get("retention_policy_id"), "policy.retention_policy_id", identifier=True),
        _boolean(item.get("enabled", True), "policy.enabled"),
        optional_limit("maximum_age_days", MAX_RETENTION_DAYS),
        optional_limit("maximum_record_count", MAX_RECORDS),
        optional_limit("maximum_total_bytes", MAX_BYTES),
        (
            _enum(Severity, item.get("retain_minimum_severity"), "policy.retain_minimum_severity")
            if item.get("retain_minimum_severity") is not None
            else None
        ),
        _boolean(item.get("retain_unresolved", True), "policy.retain_unresolved"),
        _boolean(
            item.get("retain_manual_intervention", True),
            "policy.retain_manual_intervention",
        ),
        _boolean(item.get("retain_latest_versions", True), "policy.retain_latest_versions"),
        _boolean(item.get("archive_before_delete", False), "policy.archive_before_delete"),
        _boolean(item.get("dry_run", True), "policy.dry_run"),
        _boolean(item.get("review_required", True), "policy.review_required"),
    )


def load_retention_policy(path: str | Path) -> RetentionPolicy:
    try:
        return parse_retention_policy(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
    except OSError:
        raise IncidentValidationError("cannot read retention policy") from None
    except yaml.YAMLError:
        raise IncidentValidationError("invalid retention policy syntax") from None


def parse_retention_scenario(data: Any) -> RetentionSimulationScenario:
    root = _mapping(data, "retention scenario")
    if root.get("schema_version") != SCHEMA_VERSION:
        raise IncidentValidationError("unsupported retention scenario schema version")
    scenario = RetentionSimulationScenario(
        SCHEMA_VERSION,
        _text(root.get("scenario_id"), "scenario_id", identifier=True),
        _timestamp(root.get("now"), "now"),
        _boolean(
            root.get("remove_generated_fixtures", False),
            "remove_generated_fixtures",
        ),
        _boolean(root.get("simulation", True), "simulation"),
    )
    if not scenario.simulation:
        raise UnsafeIncidentStoreError("retention simulation mode is required")
    return scenario


def load_retention_scenario(path: str | Path) -> RetentionSimulationScenario:
    try:
        return parse_retention_scenario(
            yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        )
    except OSError:
        raise IncidentValidationError("cannot read retention scenario") from None
    except yaml.YAMLError:
        raise IncidentValidationError("invalid retention scenario syntax") from None


def preview_retention(
    store: LocalIncidentStore, policy: RetentionPolicy, *, now: str
) -> RetentionPreview:
    evaluated = _timestamp(now, "now")
    records = list(store.list_records())
    latest = {
        item.incident_id: max(
            candidate.metadata.record_version
            for candidate in records
            if candidate.incident_id == item.incident_id
        )
        for item in records
    }
    ordered = sorted(records, key=lambda item: (_time(item.updated_at), item.metadata.record_id))
    total_bytes = sum(
        _confined(store.root, item.metadata.record_id).stat().st_size for item in records
    )
    candidates: list[RetentionCandidate] = []
    for index, record in enumerate(ordered):
        path = _confined(store.root, record.metadata.record_id)
        size = path.stat().st_size
        decision = RetentionDecision.RETAIN
        reason = "record retained by policy"
        unresolved = record.status not in {
            IncidentStatus.RESOLVED,
            IncidentStatus.CLOSED,
            IncidentStatus.SUPPRESSED,
            IncidentStatus.DUPLICATE,
        }
        if not policy.enabled:
            decision, reason = RetentionDecision.PROTECTED_POLICY, "retention policy disabled"
        elif policy.retain_manual_intervention and record.manual_intervention_required:
            decision, reason = (
                RetentionDecision.PROTECTED_MANUAL_INTERVENTION,
                "manual-intervention incident is protected",
            )
        elif policy.retain_unresolved and unresolved:
            decision, reason = (
                RetentionDecision.PROTECTED_UNRESOLVED,
                "unresolved incident is protected",
            )
        elif (
            policy.retain_minimum_severity is not None
            and _SEVERITY_ORDER[record.severity]
            >= _SEVERITY_ORDER[policy.retain_minimum_severity]
        ):
            decision, reason = (
                RetentionDecision.PROTECTED_SEVERITY,
                "incident severity is protected",
            )
        elif (
            policy.retain_latest_versions
            and record.metadata.record_version == latest[record.incident_id]
            and sum(1 for item in records if item.incident_id == record.incident_id) > 1
        ):
            decision, reason = (
                RetentionDecision.PROTECTED_LATEST_VERSION,
                "latest incident version is protected",
            )
        else:
            age_eligible = (
                policy.maximum_age_days is not None
                and _time(record.updated_at)
                <= _time(evaluated) - timedelta(days=policy.maximum_age_days)
            )
            count_eligible = (
                policy.maximum_record_count is not None
                and len(records) - index > policy.maximum_record_count
            )
            bytes_eligible = (
                policy.maximum_total_bytes is not None and total_bytes > policy.maximum_total_bytes
            )
            if age_eligible or count_eligible or bytes_eligible:
                decision = (
                    RetentionDecision.MANUAL_REVIEW_REQUIRED
                    if policy.review_required or policy.archive_before_delete
                    else RetentionDecision.ELIGIBLE_FOR_REMOVAL
                )
                reason = "record exceeds configured retention boundary"
        candidates.append(
            RetentionCandidate(
                record.incident_id,
                record.metadata.record_id,
                record.metadata.record_version,
                decision,
                reason,
                path.name,
                size,
            )
        )
    eligible = sum(
        item.decision is RetentionDecision.ELIGIBLE_FOR_REMOVAL for item in candidates
    )
    return RetentionPreview(
        policy.retention_policy_id,
        evaluated,
        tuple(candidates),
        len(candidates) - eligible,
        eligible,
    )


def simulate_retention(
    store: LocalIncidentStore,
    policy: RetentionPolicy,
    *,
    now: str,
    remove_generated_fixtures: bool = False,
) -> RetentionSimulationResult:
    preview = preview_retention(store, policy, now=now)
    removed: list[str] = []
    audits: list[dict[str, Any]] = []
    if remove_generated_fixtures:
        if policy.dry_run:
            raise UnsafeIncidentStoreError(
                "fixture removal requires an explicit non-dry-run simulation policy"
            )
        for item in preview.candidates:
            if item.decision is RetentionDecision.ELIGIBLE_FOR_REMOVAL:
                path = _confined(store.root, item.record_id)
                path.unlink()
                removed.append(item.record_id)
    for item in preview.candidates:
        audits.append(
            {
                "event_id": f"{item.record_id}.retention",
                "incident_id": item.incident_id,
                "timestamp": preview.evaluated_at,
                "event_type": (
                    IncidentEventType.RETENTION_SIMULATED.value
                    if remove_generated_fixtures
                    else IncidentEventType.RETENTION_PREVIEWED.value
                ),
                "retention_decision": item.decision.value,
                "simulation": True,
            }
        )
    return RetentionSimulationResult(preview, tuple(removed), tuple(audits))


def load_incident_record(path: str | Path) -> IncidentRecord:
    try:
        return parse_incident_record(json.loads(Path(path).read_text(encoding="utf-8")))
    except OSError:
        raise IncidentValidationError("cannot read incident record") from None
    except json.JSONDecodeError:
        raise IncidentValidationError("invalid incident JSON syntax") from None
