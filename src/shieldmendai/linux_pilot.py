"""Local-only, read-only, fixture-backed Linux observation pilot."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, TypeVar

import yaml

from .errors import PilotPolicyDeniedError, PilotValidationError, UnsafePilotError
from .fixture_paths import resolve_fixture_path
from .incidents import (
    IncidentEventType,
    IncidentSource,
    IncidentStatus,
    LocalIncidentStore,
    create_incident_record,
    transition_incident,
)
from .installation import validate_sandbox_root
from .models import (
    AdapterType,
    Confidence,
    ErrorClassification,
    Finding,
    FindingEvidence,
    ObservationStatus,
    ReliabilityCategory,
    Severity,
)
from .redaction import redact, sanitize_message

SCHEMA_VERSION = "1.0"
_T = TypeVar("_T")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_SENSITIVE = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:token|password|api[_-]?key|secret)\s*[:=]|"
    r"[a-z][a-z0-9+.-]*://[^/\s]+@)",
    re.IGNORECASE,
)
PILOT_ADAPTER_TYPES = frozenset(
    {
        AdapterType.SYSTEMD_SERVICE,
        AdapterType.SYSTEMD_TIMER,
        AdapterType.PROCESS,
        AdapterType.EXECUTABLE_CHECK,
        AdapterType.FILE,
        AdapterType.JSON_FILE,
        AdapterType.YAML_FILE,
        AdapterType.TOML_FILE,
        AdapterType.HTTP,
        AdapterType.TCP,
    }
)


@dataclass(frozen=True)
class LinuxObserverCapabilities:
    adapter_type: AdapterType
    observation_types: tuple[str, ...]
    read_only: bool
    fixture_simulation_available: bool
    production_adapter_available: bool
    requires_future_system_access: bool
    requires_network: bool
    requires_process_enumeration: bool
    requires_systemd: bool
    mutation_available: bool = False


@dataclass(frozen=True)
class TargetAllowlistEntry:
    target_id: str
    application_id: str
    adapter_type: AdapterType
    observation_type: str
    expected_identity: str
    fixture_root_reference: str
    allowed_read_paths: tuple[str, ...]
    denied_paths: tuple[str, ...]
    local_only: bool
    read_only: bool
    mutation_enabled: bool
    enabled: bool
    severity: Severity
    observation_interval_seconds: int
    incident_category: ReliabilityCategory


@dataclass(frozen=True)
class LinuxPilotConfiguration:
    schema_version: str
    application_id: str
    targets: tuple[TargetAllowlistEntry, ...]


@dataclass(frozen=True)
class LocalPilotPolicy:
    schema_version: str
    pilot_id: str
    enabled: bool
    local_only: bool
    read_only: bool
    sandbox_only: bool
    allowed_host_reference: str
    allowed_target_ids: tuple[str, ...]
    allowed_adapter_types: tuple[AdapterType, ...]
    prohibited_adapter_types: tuple[AdapterType, ...]
    repairs_enabled: bool
    notifications_enabled: bool
    network_enabled: bool
    process_enumeration_enabled: bool
    systemd_enabled: bool
    maximum_targets: int
    minimum_interval_seconds: int
    incident_store_reference: str
    review_required: bool


@dataclass(frozen=True)
class FixtureObservation:
    target_id: str
    state: str
    fixture_path: str | None
    duration_ms: int


@dataclass(frozen=True)
class LinuxPilotScenario:
    schema_version: str
    scenario_id: str
    observed_at: str
    host_reference: str
    requested_production_observation: bool
    requested_repair: bool
    requested_notification: bool
    observations: tuple[FixtureObservation, ...]


@dataclass(frozen=True)
class ObservationAuditEvent:
    event_id: str
    pilot_id: str
    cycle_id: str
    target_id: str
    adapter_type: AdapterType
    timestamp: str
    outcome: str
    incident_id: str | None
    local_only: bool = True
    read_only: bool = True
    network_used: bool = False
    systemd_contacted: bool = False
    process_enumerated: bool = False
    repair_executed: bool = False
    notification_sent: bool = False
    simulation: bool = True


@dataclass(frozen=True)
class LinuxPilotCycleResult:
    pilot_id: str
    cycle_id: str
    observed_at: str
    findings: tuple[Finding, ...]
    skipped_target_ids: tuple[str, ...]
    incident_references: tuple[str, ...]
    audit_events: tuple[ObservationAuditEvent, ...]
    cycle_count: int
    exit_code: int
    local_only: bool = True
    read_only: bool = True
    production_system_observed: bool = False
    repair_executed: bool = False
    notification_sent: bool = False
    network_used: bool = False
    simulation: bool = True


class FixtureLinuxObserver(Protocol):
    capabilities: LinuxObserverCapabilities

    def observe(
        self,
        target: TargetAllowlistEntry,
        observation: FixtureObservation,
        *,
        observed_at: str,
        sandbox_root: Path,
    ) -> Finding: ...


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
        raise PilotValidationError(f"{location} must be a mapping")
    return value


def _list(value: Any, location: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PilotValidationError(f"{location} must be a list")
    return value


def _reject_unknown(data: dict[str, Any], allowed: set[str], location: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PilotValidationError(f"{location} contains unknown fields: {', '.join(unknown)}")


def _text(value: Any, location: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PilotValidationError(f"{location} must be a non-empty string")
    result = sanitize_message(value.strip())
    if _SENSITIVE.search(result):
        raise PilotValidationError(f"{location} contains credential-like data")
    if identifier and not _ID.fullmatch(result):
        raise PilotValidationError(f"{location} contains unsupported characters")
    if "*" in result:
        raise PilotValidationError(f"{location} must use exact values without wildcards")
    return result


def _boolean(value: Any, location: str) -> bool:
    if not isinstance(value, bool):
        raise PilotValidationError(f"{location} must be true or false")
    return value


def _integer(value: Any, location: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise PilotValidationError(
            f"{location} must be an integer between {minimum} and {maximum}"
        )
    return value


def _enum(enum_type: type[_T], value: Any, location: str) -> _T:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        raise PilotValidationError(f"{location} is unknown") from None


def _timestamp(value: Any, location: str) -> str:
    from datetime import datetime

    result = _text(value, location)
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError:
        raise PilotValidationError(f"{location} must be an ISO-8601 timestamp") from None
    if parsed.tzinfo is None:
        raise PilotValidationError(f"{location} must include a timezone")
    return result


def _exact_ids(value: Any, location: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    result = tuple(
        _text(item, f"{location}[{index}]", identifier=True)
        for index, item in enumerate(_list(value, location))
    )
    if not result and not allow_empty:
        raise PilotValidationError(f"{location} must not be empty")
    if len(result) != len(set(result)):
        raise PilotValidationError(f"{location} contains duplicates")
    return result


def _relative_paths(value: Any, location: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    result: list[str] = []
    for index, item in enumerate(_list(value, location)):
        text = _text(item, f"{location}[{index}]")
        path = PurePosixPath(text)
        if path.is_absolute() or ".." in path.parts:
            raise PilotValidationError(f"{location} must contain confined relative paths")
        result.append(str(path))
    if not result and not allow_empty:
        raise PilotValidationError(f"{location} must not be empty")
    if len(result) != len(set(result)):
        raise PilotValidationError(f"{location} contains duplicates")
    return tuple(result)


def observer_capability_catalog() -> tuple[LinuxObserverCapabilities, ...]:
    capabilities = {
        AdapterType.SYSTEMD_SERVICE: (("service_status",), True, False, True),
        AdapterType.SYSTEMD_TIMER: (("timer_status",), True, False, True),
        AdapterType.PROCESS: (("expected_process_presence",), True, True, False),
        AdapterType.EXECUTABLE_CHECK: (("executable_presence",), True, False, False),
        AdapterType.FILE: (("file_existence", "file_readability", "file_checksum"), True, False, False),
        AdapterType.JSON_FILE: (("structured_file_validity",), True, False, False),
        AdapterType.YAML_FILE: (("structured_file_validity",), True, False, False),
        AdapterType.TOML_FILE: (("structured_file_validity",), True, False, False),
        AdapterType.HTTP: (("http_health",), True, False, False),
        AdapterType.TCP: (("tcp_port_health",), True, False, False),
    }
    result = []
    for adapter_type in sorted(capabilities, key=lambda item: item.value):
        checks, future, process, systemd = capabilities[adapter_type]
        result.append(
            LinuxObserverCapabilities(
                adapter_type,
                checks,
                True,
                True,
                False,
                future,
                adapter_type in {AdapterType.HTTP, AdapterType.TCP},
                process,
                systemd,
            )
        )
    return tuple(result)


class DisabledProductionLinuxObserver:
    def __init__(self, adapter_type: AdapterType) -> None:
        capability = next(
            item for item in observer_capability_catalog() if item.adapter_type is adapter_type
        )
        self.capabilities = capability

    def observe(self, *_: Any, **__: Any) -> Finding:
        raise UnsafePilotError(
            "production Linux observation is disabled outside a separately approved future pilot"
        )


def parse_pilot_configuration(data: Any) -> LinuxPilotConfiguration:
    root = _mapping(data, "pilot configuration")
    _reject_unknown(root, {"schema_version", "application_id", "targets"}, "pilot configuration")
    if root.get("schema_version") != SCHEMA_VERSION:
        raise PilotValidationError("unknown pilot configuration schema")
    application_id = _text(root.get("application_id"), "application_id", identifier=True)
    targets: list[TargetAllowlistEntry] = []
    for index, value in enumerate(_list(root.get("targets"), "targets")):
        item = _mapping(value, f"targets[{index}]")
        allowed = {
            "target_id", "application_id", "adapter_type", "observation_type",
            "expected_identity", "fixture_root_reference", "allowed_read_paths",
            "denied_paths", "local_only", "read_only", "mutation_enabled", "enabled",
            "severity", "observation_interval_seconds", "incident_category",
        }
        _reject_unknown(item, allowed, f"targets[{index}]")
        target = TargetAllowlistEntry(
            _text(item.get("target_id"), f"targets[{index}].target_id", identifier=True),
            _text(item.get("application_id"), f"targets[{index}].application_id", identifier=True),
            _enum(AdapterType, item.get("adapter_type"), f"targets[{index}].adapter_type"),
            _text(item.get("observation_type"), f"targets[{index}].observation_type", identifier=True),
            _text(item.get("expected_identity"), f"targets[{index}].expected_identity", identifier=True),
            _text(item.get("fixture_root_reference"), f"targets[{index}].fixture_root_reference", identifier=True),
            _relative_paths(item.get("allowed_read_paths", []), f"targets[{index}].allowed_read_paths", allow_empty=True),
            _relative_paths(item.get("denied_paths", []), f"targets[{index}].denied_paths", allow_empty=True),
            _boolean(item.get("local_only"), f"targets[{index}].local_only"),
            _boolean(item.get("read_only"), f"targets[{index}].read_only"),
            _boolean(item.get("mutation_enabled", False), f"targets[{index}].mutation_enabled"),
            _boolean(item.get("enabled", True), f"targets[{index}].enabled"),
            _enum(Severity, item.get("severity"), f"targets[{index}].severity"),
            _integer(
                item.get("observation_interval_seconds"),
                f"targets[{index}].observation_interval_seconds",
                1,
                86_400,
            ),
            _enum(
                ReliabilityCategory,
                item.get("incident_category"),
                f"targets[{index}].incident_category",
            ),
        )
        if target.application_id != application_id:
            raise PilotValidationError("target application ID must exactly match configuration")
        if target.adapter_type not in PILOT_ADAPTER_TYPES:
            raise PilotValidationError("unknown Linux pilot adapter")
        if not target.local_only:
            raise PilotPolicyDeniedError("non-local target is denied")
        if not target.read_only or target.mutation_enabled:
            raise PilotPolicyDeniedError("mutation-enabled target is denied")
        if set(target.allowed_read_paths) & set(target.denied_paths):
            raise PilotValidationError("target has conflicting allowed and denied paths")
        targets.append(target)
    ids = [item.target_id for item in targets]
    if len(ids) != len(set(ids)):
        raise PilotValidationError("target allowlist contains duplicate target IDs")
    identities = [(item.adapter_type, item.expected_identity) for item in targets]
    if len(identities) != len(set(identities)):
        raise PilotValidationError("target allowlist contains duplicate conflicting identities")
    return LinuxPilotConfiguration(SCHEMA_VERSION, application_id, tuple(targets))


def load_pilot_configuration(path: str | Path) -> LinuxPilotConfiguration:
    try:
        return parse_pilot_configuration(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError):
        raise PilotValidationError("pilot configuration could not be loaded") from None


def parse_pilot_policy(data: Any) -> LocalPilotPolicy:
    root = _mapping(data, "pilot policy")
    allowed = {
        "schema_version", "pilot_id", "enabled", "local_only", "read_only",
        "sandbox_only", "allowed_host_reference", "allowed_target_ids",
        "allowed_adapter_types", "prohibited_adapter_types", "repairs_enabled",
        "notifications_enabled", "network_enabled", "process_enumeration_enabled",
        "systemd_enabled", "maximum_targets", "minimum_interval_seconds",
        "incident_store_reference", "review_required",
    }
    _reject_unknown(root, allowed, "pilot policy")
    if root.get("schema_version") != SCHEMA_VERSION:
        raise PilotValidationError("unknown pilot policy schema")
    adapters = tuple(
        _enum(AdapterType, item, "allowed_adapter_types")
        for item in _list(root.get("allowed_adapter_types"), "allowed_adapter_types")
    )
    prohibited = tuple(
        _enum(AdapterType, item, "prohibited_adapter_types")
        for item in _list(root.get("prohibited_adapter_types", []), "prohibited_adapter_types")
    )
    if len(adapters) != len(set(adapters)) or len(prohibited) != len(set(prohibited)):
        raise PilotValidationError("pilot adapter lists contain duplicates")
    if set(adapters) & set(prohibited):
        raise PilotValidationError("pilot adapter lists conflict")
    policy = LocalPilotPolicy(
        SCHEMA_VERSION,
        _text(root.get("pilot_id"), "pilot_id", identifier=True),
        _boolean(root.get("enabled", True), "enabled"),
        _boolean(root.get("local_only", True), "local_only"),
        _boolean(root.get("read_only", True), "read_only"),
        _boolean(root.get("sandbox_only", True), "sandbox_only"),
        _text(root.get("allowed_host_reference"), "allowed_host_reference", identifier=True),
        _exact_ids(root.get("allowed_target_ids"), "allowed_target_ids"),
        adapters,
        prohibited,
        _boolean(root.get("repairs_enabled", False), "repairs_enabled"),
        _boolean(root.get("notifications_enabled", False), "notifications_enabled"),
        _boolean(root.get("network_enabled", False), "network_enabled"),
        _boolean(root.get("process_enumeration_enabled", False), "process_enumeration_enabled"),
        _boolean(root.get("systemd_enabled", False), "systemd_enabled"),
        _integer(root.get("maximum_targets", 1), "maximum_targets", 1, 100),
        _integer(root.get("minimum_interval_seconds", 60), "minimum_interval_seconds", 1, 86_400),
        _relative_paths(
            [root.get("incident_store_reference")], "incident_store_reference"
        )[0],
        _boolean(root.get("review_required", True), "review_required"),
    )
    if not policy.enabled:
        raise PilotPolicyDeniedError("pilot policy is disabled")
    if not policy.local_only or not policy.read_only or not policy.sandbox_only:
        raise UnsafePilotError("pilot policy must remain local, read-only, and sandbox-only")
    if policy.repairs_enabled or policy.notifications_enabled or policy.network_enabled:
        raise UnsafePilotError("repair, notification, and network capabilities must remain disabled")
    if policy.process_enumeration_enabled or policy.systemd_enabled:
        raise UnsafePilotError("real process and systemd access must remain disabled")
    if not policy.review_required:
        raise PilotValidationError("pilot policy requires review")
    if len(policy.allowed_target_ids) > policy.maximum_targets:
        raise PilotValidationError("allowed targets exceed policy maximum")
    return policy


def load_pilot_policy(path: str | Path) -> LocalPilotPolicy:
    try:
        return parse_pilot_policy(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError):
        raise PilotValidationError("pilot policy could not be loaded") from None


def parse_pilot_scenario(data: Any) -> LinuxPilotScenario:
    root = _mapping(data, "pilot scenario")
    allowed = {
        "schema_version", "scenario_id", "observed_at", "host_reference",
        "requested_production_observation", "requested_repair",
        "requested_notification", "observations",
    }
    _reject_unknown(root, allowed, "pilot scenario")
    if root.get("schema_version") != SCHEMA_VERSION:
        raise PilotValidationError("unknown pilot scenario schema")
    observations: list[FixtureObservation] = []
    for index, value in enumerate(_list(root.get("observations"), "observations")):
        item = _mapping(value, f"observations[{index}]")
        _reject_unknown(item, {"target_id", "state", "fixture_path", "duration_ms"}, f"observations[{index}]")
        fixture_path = item.get("fixture_path")
        observations.append(
            FixtureObservation(
                _text(item.get("target_id"), f"observations[{index}].target_id", identifier=True),
                _text(item.get("state"), f"observations[{index}].state", identifier=True),
                None if fixture_path is None else _relative_paths([fixture_path], "fixture_path")[0],
                _integer(item.get("duration_ms", 0), f"observations[{index}].duration_ms", 0, 60_000),
            )
        )
    ids = [item.target_id for item in observations]
    if len(ids) != len(set(ids)):
        raise PilotValidationError("pilot scenario contains duplicate targets")
    return LinuxPilotScenario(
        SCHEMA_VERSION,
        _text(root.get("scenario_id"), "scenario_id", identifier=True),
        _timestamp(root.get("observed_at"), "observed_at"),
        _text(root.get("host_reference"), "host_reference", identifier=True),
        _boolean(root.get("requested_production_observation", False), "requested_production_observation"),
        _boolean(root.get("requested_repair", False), "requested_repair"),
        _boolean(root.get("requested_notification", False), "requested_notification"),
        tuple(observations),
    )


def load_pilot_scenario(path: str | Path) -> LinuxPilotScenario:
    try:
        return parse_pilot_scenario(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError):
        raise PilotValidationError("pilot scenario could not be loaded") from None


def _finding(
    target: TargetAllowlistEntry,
    observation: FixtureObservation,
    observed_at: str,
    *,
    healthy: bool,
    summary: str,
    observed: str,
    evidence: dict[str, Any],
    error: ErrorClassification = ErrorClassification.NONE,
) -> Finding:
    return Finding(
        target.target_id,
        target.adapter_type,
        observed_at,
        ObservationStatus.HEALTHY if healthy else ObservationStatus.UNHEALTHY,
        Severity.INFO if healthy else target.severity,
        None if healthy else target.incident_category,
        Confidence.DETERMINISTIC,
        summary,
        FindingEvidence(redact(evidence)),
        target.expected_identity,
        observed,
        observation.duration_ms,
        error,
        not healthy,
        not healthy,
        True,
        "1.0",
    )


class ScenarioStateObserver:
    def __init__(self, adapter_type: AdapterType) -> None:
        self.capabilities = next(
            item for item in observer_capability_catalog() if item.adapter_type is adapter_type
        )

    def observe(
        self,
        target: TargetAllowlistEntry,
        observation: FixtureObservation,
        *,
        observed_at: str,
        sandbox_root: Path,
    ) -> Finding:
        del sandbox_root
        healthy_states = {
            AdapterType.SYSTEMD_SERVICE: "active",
            AdapterType.SYSTEMD_TIMER: "active",
            AdapterType.PROCESS: "present",
            AdapterType.HTTP: "healthy",
            AdapterType.TCP: "reachable",
        }
        expected = healthy_states.get(target.adapter_type)
        if target.adapter_type in {AdapterType.HTTP, AdapterType.TCP}:
            raise PilotPolicyDeniedError("network adapters remain disabled in Phase 7")
        healthy = observation.state == expected
        return _finding(
            target,
            observation,
            observed_at,
            healthy=healthy,
            summary="Fixture observation is healthy" if healthy else "Fixture observation is unhealthy",
            observed=observation.state,
            evidence={"fixture_state": observation.state, "identity": target.expected_identity},
            error=ErrorClassification.NONE if healthy else ErrorClassification.SIMULATED_FAILURE,
        )


class FixturePathObserver:
    def __init__(self, adapter_type: AdapterType) -> None:
        self.capabilities = next(
            item for item in observer_capability_catalog() if item.adapter_type is adapter_type
        )

    def observe(
        self,
        target: TargetAllowlistEntry,
        observation: FixtureObservation,
        *,
        observed_at: str,
        sandbox_root: Path,
    ) -> Finding:
        if observation.fixture_path is None:
            raise PilotValidationError("fixture-backed file observation requires fixture_path")
        if observation.fixture_path not in target.allowed_read_paths:
            raise PilotPolicyDeniedError("fixture path is not exactly allowlisted")
        if observation.fixture_path in target.denied_paths:
            raise PilotPolicyDeniedError("fixture path is explicitly denied")
        path = resolve_fixture_path(sandbox_root, observation.fixture_path)
        exists = path.exists() and path.is_file()
        valid = exists
        evidence: dict[str, Any] = {"fixture_path": observation.fixture_path, "exists": exists}
        if exists and target.adapter_type in {
            AdapterType.JSON_FILE,
            AdapterType.YAML_FILE,
            AdapterType.TOML_FILE,
        }:
            try:
                text = path.read_text(encoding="utf-8")
                if target.adapter_type is AdapterType.JSON_FILE:
                    json.loads(text)
                elif target.adapter_type is AdapterType.YAML_FILE:
                    yaml.safe_load(text)
                else:
                    import tomllib

                    tomllib.loads(text)
            except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError):
                valid = False
            evidence["structured_valid"] = valid
        if exists:
            evidence["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        return _finding(
            target,
            observation,
            observed_at,
            healthy=valid,
            summary="Fixture path observation is healthy" if valid else "Fixture path observation is unhealthy",
            observed="present_and_valid" if valid else "missing_or_invalid",
            evidence=evidence,
            error=ErrorClassification.NONE if valid else ErrorClassification.NOT_FOUND,
        )


class FixtureObserverRegistry:
    def __init__(self) -> None:
        self._adapters: dict[AdapterType, FixtureLinuxObserver] = {}
        for adapter_type in PILOT_ADAPTER_TYPES:
            if adapter_type in {
                AdapterType.FILE,
                AdapterType.JSON_FILE,
                AdapterType.YAML_FILE,
                AdapterType.TOML_FILE,
                AdapterType.EXECUTABLE_CHECK,
            }:
                self._adapters[adapter_type] = FixturePathObserver(adapter_type)
            else:
                self._adapters[adapter_type] = ScenarioStateObserver(adapter_type)

    def get(self, adapter_type: AdapterType) -> FixtureLinuxObserver:
        try:
            return self._adapters[adapter_type]
        except KeyError:
            raise PilotPolicyDeniedError("unknown Linux pilot adapter") from None


def _latest_incident(store: LocalIncidentStore, incident_id: str):
    records = [item for item in store.list_records() if item.incident_id == incident_id]
    return max(records, key=lambda item: item.metadata.record_version) if records else None


class LinuxPilotController:
    def __init__(self, registry: FixtureObserverRegistry | None = None) -> None:
        self._registry = registry or FixtureObserverRegistry()

    def run_cycle(
        self,
        config: LinuxPilotConfiguration,
        policy: LocalPilotPolicy,
        scenario: LinuxPilotScenario,
        sandbox_root: str | Path,
    ) -> LinuxPilotCycleResult:
        root = validate_sandbox_root(sandbox_root)
        if scenario.requested_production_observation:
            raise UnsafePilotError("production observation is disabled")
        if scenario.requested_repair:
            raise UnsafePilotError("repair execution is disabled")
        if scenario.requested_notification:
            raise UnsafePilotError("notification delivery is disabled")
        if scenario.host_reference != policy.allowed_host_reference:
            raise PilotPolicyDeniedError("host reference is not exactly allowlisted")
        targets = {item.target_id: item for item in config.targets}
        scenario_ids = {item.target_id for item in scenario.observations}
        unknown = scenario_ids - set(targets)
        if unknown:
            raise PilotPolicyDeniedError("scenario references an unknown target")
        disallowed = scenario_ids - set(policy.allowed_target_ids)
        if disallowed:
            raise PilotPolicyDeniedError("target is denied by exact pilot allowlist")
        if len(scenario_ids) > policy.maximum_targets:
            raise PilotPolicyDeniedError("pilot target maximum exceeded")
        incident_root = root.joinpath(*PurePosixPath(policy.incident_store_reference).parts)
        existing_parent = incident_root
        while not existing_parent.exists() and existing_parent != root:
            existing_parent = existing_parent.parent
        if not existing_parent.resolve(strict=True).is_relative_to(root):
            raise UnsafePilotError("incident store reference escapes sandbox")
        if any(
            item.exists() and item.is_symlink()
            for item in (incident_root, *incident_root.parents)
            if item != root and item.is_relative_to(root)
        ):
            raise UnsafePilotError("incident store reference cannot traverse symlinks")
        incident_root.mkdir(parents=True, exist_ok=True)
        store = LocalIncidentStore(incident_root)
        findings: list[Finding] = []
        skipped: list[str] = []
        incidents: list[str] = []
        audits: list[ObservationAuditEvent] = []
        cycle_id = f"{policy.pilot_id}.{scenario.scenario_id}"
        observations = {item.target_id: item for item in scenario.observations}
        for target_id in policy.allowed_target_ids:
            target = targets.get(target_id)
            if target is None:
                raise PilotPolicyDeniedError("policy references an unknown target")
            if not target.enabled:
                skipped.append(target_id)
                continue
            if target.adapter_type not in policy.allowed_adapter_types:
                raise PilotPolicyDeniedError("target adapter is not exactly allowlisted")
            if target.adapter_type in policy.prohibited_adapter_types:
                raise PilotPolicyDeniedError("target adapter is prohibited")
            if target.observation_interval_seconds < policy.minimum_interval_seconds:
                raise PilotPolicyDeniedError("target interval is below policy minimum")
            observation = observations.get(target_id)
            if observation is None:
                continue
            adapter = self._registry.get(target.adapter_type)
            if not adapter.capabilities.read_only or adapter.capabilities.mutation_available:
                raise UnsafePilotError("observer capability is not read-only")
            finding = adapter.observe(
                target,
                observation,
                observed_at=scenario.observed_at,
                sandbox_root=root,
            )
            findings.append(finding)
            incident_id = f"pilot-{target.target_id}"
            latest = _latest_incident(store, incident_id)
            linked: str | None = None
            if finding.status is ObservationStatus.UNHEALTHY:
                if latest is None:
                    created = create_incident_record(
                        incident_id=incident_id,
                        application_id=target.application_id,
                        target_id=target.target_id,
                        adapter_type=target.adapter_type,
                        category=target.incident_category,
                        severity=target.severity,
                        confidence=Confidence.DETERMINISTIC,
                        summary=finding.summary,
                        sanitized_description="Fixture-backed read-only pilot finding.",
                        timestamp=scenario.observed_at,
                        source=IncidentSource.OBSERVATION,
                        tags=("phase7", "sandbox", "read_only"),
                    )
                    store.write(created)
                    latest = transition_incident(
                        created,
                        IncidentStatus.OPEN,
                        timestamp=scenario.observed_at,
                        event_type=IncidentEventType.FINDING_RECORDED,
                        reason_code="fixture_finding_unhealthy",
                        sanitized_message="Fixture-backed unhealthy finding recorded.",
                    )
                    store.write(latest)
                linked = latest.incident_id
                incidents.append(linked)
            elif latest is not None and latest.status in {
                IncidentStatus.OPEN,
                IncidentStatus.ACKNOWLEDGED,
                IncidentStatus.INVESTIGATING,
                IncidentStatus.REMEDIATION_PLANNED,
                IncidentStatus.MONITORING_VERIFICATION,
            }:
                resolved = transition_incident(
                    latest,
                    IncidentStatus.RESOLVED,
                    timestamp=scenario.observed_at,
                    event_type=IncidentEventType.VERIFICATION_SUCCEEDED,
                    reason_code="fixture_recheck_healthy",
                    sanitized_message="Fixture-backed healthy recheck resolved the incident.",
                )
                store.write(resolved)
                linked = resolved.incident_id
                incidents.append(linked)
            audits.append(
                ObservationAuditEvent(
                    f"{cycle_id}.{target.target_id}",
                    policy.pilot_id,
                    cycle_id,
                    target.target_id,
                    target.adapter_type,
                    scenario.observed_at,
                    finding.status.value,
                    linked,
                )
            )
        exit_code = 3 if any(
            item.status not in {ObservationStatus.HEALTHY, ObservationStatus.SKIPPED}
            for item in findings
        ) else 0
        return LinuxPilotCycleResult(
            policy.pilot_id,
            cycle_id,
            scenario.observed_at,
            tuple(findings),
            tuple(skipped),
            tuple(dict.fromkeys(incidents)),
            tuple(audits),
            1,
            exit_code,
        )


def safe_pilot_dict(value: Any) -> dict[str, Any] | list[Any]:
    return redact(_primitive(value))
