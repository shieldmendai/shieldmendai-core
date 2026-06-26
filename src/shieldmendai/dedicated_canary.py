"""Dedicated-server read-only canary deployment package model."""

from __future__ import annotations

import hashlib
import json
import re
import socket
import tempfile
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, TypeVar

import yaml

from . import __version__
from .errors import InstallationConflictError, InstallationValidationError, PilotPolicyDeniedError
from .incidents import (
    IncidentEventType,
    IncidentSource,
    IncidentStatus,
    LocalIncidentStore,
    create_incident_record,
    transition_incident,
)
from .models import AdapterType, Confidence, ObservationStatus, ReliabilityCategory, Severity
from .redaction import redact, sanitize_message

SCHEMA_VERSION = "1.0"
CANARY_APPLICATION_ID = "shieldmendai-dedicated-canary"
CANARY_IDENTITY = "shieldmendai-dedicated-read-only-canary"
DEMO_TARGET_ID = "shieldmendai-demo-health-json"
DEMO_SERVICE = "shieldmendai-demo.service"
MANIFEST_NAME = "shieldmendai-canary-installation-manifest.json"
AUDIT_NAME = "shieldmendai-canary-installation-audit.json"
FORBIDDEN_PRIVATE_PATH = "/root/" + "newbasebot"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_T = TypeVar("_T")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_IP_ADDRESS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SENSITIVE = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE" r" KEY-----|(?:token|pass" r"word|api[_-]?key|secret|wallet)\s*[:=]|"
    r"[a-z][a-z0-9+.-]*://[^/\s]+@)",
    re.IGNORECASE,
)


class CanaryAction(str, Enum):
    INSTALL_PREVIEW = "installation_preview"
    INSTALL_APPLY = "installation_apply"
    OBSERVE = "read_only_canary_observation"
    DELIBERATE_FAILURE = "deliberate_demo_failure"
    MANUAL_RECOVERY = "manual_demo_recovery"
    ROLLBACK_PREVIEW = "rollback_preview"
    ROLLBACK_APPLY = "rollback_apply"
    VERIFY = "verification_only"


@dataclass(frozen=True)
class DedicatedCanaryTarget:
    target_id: str
    adapter_type: AdapterType
    local_only: bool
    read_only: bool
    mutation_enabled: bool
    network_required: bool
    allowed_read_paths: tuple[str, ...]
    incident_category: ReliabilityCategory
    severity: Severity


@dataclass(frozen=True)
class DedicatedCanaryConfig:
    schema_version: str
    application_id: str
    canary_identity: str
    expected_hostname: str
    environment: str
    local_only: bool
    read_only: bool
    observation_enabled: bool
    repairs_enabled: bool
    notification_delivery_enabled: bool
    network_access_enabled: bool
    process_enumeration_enabled: bool
    automatic_target_discovery: bool
    incident_store_path: str
    state_store_path: str
    log_level: str
    observation_interval_seconds: int
    targets: tuple[DedicatedCanaryTarget, ...]


@dataclass(frozen=True)
class CanaryHostValidation:
    expected_hostname: str
    actual_hostname: str
    canary_identity: str | None
    accepted: bool
    reason: str


@dataclass(frozen=True)
class CanaryFileRecord:
    path: str
    sha256: str
    size_bytes: int
    mode: str


@dataclass(frozen=True)
class CanaryManifest:
    schema_version: str
    application_id: str
    canary_identity: str
    package_version: str
    install_root: str
    files: tuple[CanaryFileRecord, ...]
    audit_sha256: str
    manifest_checksum: str


@dataclass(frozen=True)
class CanaryOperationResult:
    action: CanaryAction
    preview_only: bool
    apply_requested: bool
    changed: bool
    host_validation: CanaryHostValidation | None
    planned_files: tuple[str, ...]
    created_or_updated_files: tuple[str, ...]
    removed_files: tuple[str, ...]
    preserved_files: tuple[str, ...]
    conflicts: tuple[str, ...]
    manifest: CanaryManifest | None = None
    audit_record: dict[str, Any] | None = None


@dataclass(frozen=True)
class CanaryObservationResult:
    action: CanaryAction
    target_id: str
    status: ObservationStatus
    incident_references: tuple[str, ...]
    repair_executed: bool
    notification_sent: bool
    network_used: bool
    process_mutation_used: bool
    cycle_count: int
    summary: str


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


def safe_canary_dict(value: Any) -> dict[str, Any] | list[Any]:
    return redact(_primitive(value))


def _mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InstallationValidationError(f"{location} must be a mapping")
    return value


def _list(value: Any, location: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise InstallationValidationError(f"{location} must be a list")
    return value


def _reject_unknown(data: dict[str, Any], allowed: set[str], location: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise InstallationValidationError(f"{location} contains unknown fields: {', '.join(unknown)}")


def _text(value: Any, location: str, *, identifier: bool = False, path: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InstallationValidationError(f"{location} must be a non-empty string")
    result = sanitize_message(value.strip())
    if _SENSITIVE.search(result):
        raise InstallationValidationError(f"{location} contains credential-like data")
    if _IP_ADDRESS.search(result):
        raise InstallationValidationError(f"{location} must not contain a real IP address")
    if FORBIDDEN_PRIVATE_PATH in result:
        raise InstallationValidationError(f"{location} contains a prohibited private path")
    if "*" in result:
        raise InstallationValidationError(f"{location} must not contain wildcards")
    if identifier and not _ID.fullmatch(result):
        raise InstallationValidationError(f"{location} contains unsupported characters")
    if path:
        pure = PurePosixPath(result)
        if not pure.is_absolute() or ".." in pure.parts:
            raise InstallationValidationError(f"{location} must be an absolute normalized path")
    return result


def _boolean(value: Any, location: str) -> bool:
    if not isinstance(value, bool):
        raise InstallationValidationError(f"{location} must be true or false")
    return value


def _integer(value: Any, location: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise InstallationValidationError(f"{location} must be an integer between {minimum} and {maximum}")
    return value


def _enum(enum_type: type[_T], value: Any, location: str) -> _T:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        raise InstallationValidationError(f"{location} is unknown") from None


def parse_canary_config(data: Any) -> DedicatedCanaryConfig:
    root = _mapping(data, "dedicated canary configuration")
    allowed = {
        "schema_version", "application_id", "canary_identity", "expected_hostname",
        "environment", "local_only", "read_only", "observation_enabled",
        "repairs_enabled", "notification_delivery_enabled", "network_access_enabled",
        "process_enumeration_enabled", "automatic_target_discovery",
        "incident_store_path", "state_store_path", "log_level",
        "observation_interval_seconds", "targets",
    }
    _reject_unknown(root, allowed, "dedicated canary configuration")
    if root.get("schema_version") != SCHEMA_VERSION:
        raise InstallationValidationError("unknown dedicated canary schema")
    targets: list[DedicatedCanaryTarget] = []
    for index, raw in enumerate(_list(root.get("targets"), "targets")):
        item = _mapping(raw, f"targets[{index}]")
        _reject_unknown(
            item,
            {
                "target_id", "adapter_type", "local_only", "read_only",
                "mutation_enabled", "network_required", "allowed_read_paths",
                "incident_category", "severity",
            },
            f"targets[{index}]",
        )
        read_paths = tuple(
            _text(path, f"targets[{index}].allowed_read_paths", path=True)
            for path in _list(item.get("allowed_read_paths"), "allowed_read_paths")
        )
        target = DedicatedCanaryTarget(
            _text(item.get("target_id"), f"targets[{index}].target_id", identifier=True),
            _enum(AdapterType, item.get("adapter_type"), f"targets[{index}].adapter_type"),
            _boolean(item.get("local_only"), f"targets[{index}].local_only"),
            _boolean(item.get("read_only"), f"targets[{index}].read_only"),
            _boolean(item.get("mutation_enabled", False), f"targets[{index}].mutation_enabled"),
            _boolean(item.get("network_required", False), f"targets[{index}].network_required"),
            read_paths,
            _enum(ReliabilityCategory, item.get("incident_category"), f"targets[{index}].incident_category"),
            _enum(Severity, item.get("severity"), f"targets[{index}].severity"),
        )
        if not target.local_only:
            raise PilotPolicyDeniedError("non-local target is denied")
        if not target.read_only or target.mutation_enabled:
            raise PilotPolicyDeniedError("mutation-enabled target is denied")
        if target.network_required:
            raise PilotPolicyDeniedError("network target is denied")
        targets.append(target)
    ids = [item.target_id for item in targets]
    if len(ids) != len(set(ids)):
        raise InstallationValidationError("target allowlist contains duplicates")
    config = DedicatedCanaryConfig(
        SCHEMA_VERSION,
        _text(root.get("application_id"), "application_id", identifier=True),
        _text(root.get("canary_identity"), "canary_identity", identifier=True),
        _text(root.get("expected_hostname"), "expected_hostname", identifier=True),
        _text(root.get("environment"), "environment", identifier=True),
        _boolean(root.get("local_only"), "local_only"),
        _boolean(root.get("read_only"), "read_only"),
        _boolean(root.get("observation_enabled"), "observation_enabled"),
        _boolean(root.get("repairs_enabled"), "repairs_enabled"),
        _boolean(root.get("notification_delivery_enabled"), "notification_delivery_enabled"),
        _boolean(root.get("network_access_enabled"), "network_access_enabled"),
        _boolean(root.get("process_enumeration_enabled"), "process_enumeration_enabled"),
        _boolean(root.get("automatic_target_discovery"), "automatic_target_discovery"),
        _text(root.get("incident_store_path"), "incident_store_path", path=True),
        _text(root.get("state_store_path"), "state_store_path", path=True),
        _text(root.get("log_level"), "log_level", identifier=True),
        _integer(root.get("observation_interval_seconds"), "observation_interval_seconds", 60, 86_400),
        tuple(targets),
    )
    if config.application_id != CANARY_APPLICATION_ID or config.canary_identity != CANARY_IDENTITY:
        raise InstallationValidationError("dedicated canary identity does not match reviewed package")
    if not config.local_only or not config.read_only or not config.observation_enabled:
        raise InstallationValidationError("dedicated canary must remain local read-only observation")
    if (
        config.repairs_enabled
        or config.notification_delivery_enabled
        or config.network_access_enabled
        or config.process_enumeration_enabled
        or config.automatic_target_discovery
    ):
        raise InstallationValidationError("repairs, notifications, network, process enumeration, and discovery must remain disabled")
    if tuple(ids) != (DEMO_TARGET_ID,):
        raise PilotPolicyDeniedError("dedicated canary only accepts the exact demo target")
    return config


def load_canary_config(path: str | Path) -> DedicatedCanaryConfig:
    try:
        return parse_canary_config(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError):
        raise InstallationValidationError("dedicated canary configuration could not be loaded") from None


def default_canary_config() -> DedicatedCanaryConfig:
    return parse_canary_config(
        {
            "schema_version": SCHEMA_VERSION,
            "application_id": CANARY_APPLICATION_ID,
            "canary_identity": CANARY_IDENTITY,
            "expected_hostname": "shieldmendai",
            "environment": "dedicated_canary",
            "local_only": True,
            "read_only": True,
            "observation_enabled": True,
            "repairs_enabled": False,
            "notification_delivery_enabled": False,
            "network_access_enabled": False,
            "process_enumeration_enabled": False,
            "automatic_target_discovery": False,
            "incident_store_path": "/var/lib/shieldmendai/incidents",
            "state_store_path": "/var/lib/shieldmendai",
            "log_level": "INFO",
            "observation_interval_seconds": 300,
            "targets": [
                {
                    "target_id": DEMO_TARGET_ID,
                    "adapter_type": "json_file",
                    "local_only": True,
                    "read_only": True,
                    "mutation_enabled": False,
                    "network_required": False,
                    "allowed_read_paths": ["/var/lib/shieldmendai/demo/health.json"],
                    "incident_category": "application_test_failure",
                    "severity": "low",
                }
            ],
        }
    )


def validate_host_identity(
    config: DedicatedCanaryConfig,
    *,
    actual_hostname: str | None = None,
    canary_identity: str | None = None,
) -> CanaryHostValidation:
    actual = sanitize_message(actual_hostname or socket.gethostname())
    if _IP_ADDRESS.search(actual):
        raise InstallationValidationError("host validation must not use a public IP address")
    accepted = actual == config.expected_hostname or canary_identity == config.canary_identity
    reason = "hostname matched" if actual == config.expected_hostname else "explicit canary identity matched"
    if not accepted:
        reason = "host identity mismatch"
    return CanaryHostValidation(config.expected_hostname, actual, canary_identity, accepted, reason)


def validate_canary_root(root: str | Path, *, live_reviewed: bool = False) -> Path:
    candidate = Path(root)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise InstallationValidationError("canary install root must be an absolute normalized path")
    raw = str(candidate)
    if raw == FORBIDDEN_PRIVATE_PATH or raw.startswith(FORBIDDEN_PRIVATE_PATH + "/"):
        raise InstallationValidationError("prohibited private path rejected")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise InstallationValidationError("canary install root must already exist") from None
    if candidate.is_symlink() or candidate.absolute() != resolved:
        raise InstallationValidationError("canary install root cannot be a symlink or traverse symlinks")
    if resolved == REPOSITORY_ROOT or resolved.is_relative_to(REPOSITORY_ROOT):
        raise InstallationValidationError("repository/source server paths are rejected")
    if live_reviewed and resolved == Path("/"):
        return resolved
    if not resolved.is_relative_to(Path(tempfile.gettempdir()).resolve(strict=True)):
        raise InstallationValidationError("this package model may only be applied to temporary test roots")
    return resolved


def render_canary_systemd_units() -> dict[str, str]:
    common_service = """[Unit]
Description={description}
After=local-fs.target

[Service]
Type=oneshot
User=shieldmendai
Group=shieldmendai
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictNamespaces=true
CapabilityBoundingSet=
AmbientCapabilities=
PrivateNetwork=true
IPAddressDeny=any
RestrictAddressFamilies=AF_UNIX
ReadOnlyPaths=/etc/shieldmendai /opt/shieldmendai /var/lib/shieldmendai/demo/health.json
ReadWritePaths=/var/lib/shieldmendai /var/lib/shieldmendai/incidents /var/log/shieldmendai /run/shieldmendai
ExecStart={exec_start}
"""
    return {
        "shieldmendai-observer.service": common_service.format(
            description="ShieldMendAi read-only dedicated canary observer",
            exec_start="/opt/shieldmendai/bin/shieldmendai canary-observe / --config-path /etc/shieldmendai/dedicated-canary.yaml --live-reviewed",
        ),
        "shieldmendai-observer.timer": """[Unit]
Description=Schedule ShieldMendAi read-only dedicated canary observation

[Timer]
OnBootSec=5m
OnUnitActiveSec=5m
AccuracySec=30s
RandomizedDelaySec=0
Persistent=false
Unit=shieldmendai-observer.service

[Install]
WantedBy=timers.target
""",
        "shieldmendai-incident-maintenance.service": common_service.format(
            description="ShieldMendAi local incident maintenance preview",
            exec_start="/opt/shieldmendai/bin/shieldmendai preview-retention /var/lib/shieldmendai/incidents /etc/shieldmendai/retention.yaml",
        ),
        "shieldmendai-incident-maintenance.timer": """[Unit]
Description=Schedule ShieldMendAi local incident maintenance preview

[Timer]
OnCalendar=daily
AccuracySec=5m
Persistent=false
Unit=shieldmendai-incident-maintenance.service

[Install]
WantedBy=timers.target
""",
        DEMO_SERVICE: """[Unit]
Description=ShieldMendAi canary demo target
After=local-fs.target

[Service]
Type=simple
User=shieldmendai
Group=shieldmendai
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictNamespaces=true
CapabilityBoundingSet=
AmbientCapabilities=
PrivateNetwork=true
IPAddressDeny=any
RestrictAddressFamilies=AF_UNIX
ReadOnlyPaths=/opt/shieldmendai
ReadWritePaths=/var/lib/shieldmendai /var/log/shieldmendai /run/shieldmendai
ExecStart=/opt/shieldmendai/bin/shieldmendai-demo-service
Restart=no
""",
    }


def _canary_config_yaml(config: DedicatedCanaryConfig) -> str:
    return yaml.safe_dump(safe_canary_dict(config), sort_keys=True)


def _demo_service_script() -> str:
    return """#!/usr/bin/env python3
\"\"\"ShieldMendAi canary demo target: writes deterministic local health JSON only.\"\"\"
import json
import os
import time
from pathlib import Path

health_path = Path(os.environ.get("SHIELDMENDAI_DEMO_HEALTH", "/var/lib/shieldmendai/demo/health.json"))
health_path.parent.mkdir(parents=True, exist_ok=True)
payload = {
    "schema_version": "1.0",
    "application_id": "shieldmendai-dedicated-canary",
    "target_id": "shieldmendai-demo-health-json",
    "status": "healthy",
    "demo": True,
    "network": "disabled",
    "repair": "disabled",
}
health_path.write_text(json.dumps(payload, sort_keys=True) + "\\n", encoding="utf-8")
while True:
    time.sleep(300)
"""


def _observer_stub() -> str:
    return """#!/usr/bin/env python3
from shieldmendai.cli import main
raise SystemExit(main())
"""


def _relative_install_files(config: DedicatedCanaryConfig) -> dict[str, bytes]:
    files: dict[str, bytes] = {
        "etc/shieldmendai/dedicated-canary.yaml": _canary_config_yaml(config).encode(),
        "etc/shieldmendai/retention.yaml": yaml.safe_dump(
            {
                "schema_version": "1.0",
                "retention_policy_id": "dedicated-canary-retention-preview",
                "enabled": True,
                "maximum_age_days": 30,
                "maximum_record_count": 1000,
                "maximum_total_bytes": 100000000,
                "retain_unresolved": True,
                "retain_manual_intervention": True,
                "retain_latest_versions": True,
                "archive_before_delete": False,
                "dry_run": True,
                "review_required": True,
            },
            sort_keys=True,
        ).encode(),
        "opt/shieldmendai/bin/shieldmendai": _observer_stub().encode(),
        "opt/shieldmendai/bin/shieldmendai-demo-service": _demo_service_script().encode(),
        "var/lib/shieldmendai/demo/health.json": (
            '{"application_id":"shieldmendai-dedicated-canary","demo":true,'
            '"network":"disabled","repair":"disabled","schema_version":"1.0",'
            '"status":"healthy","target_id":"shieldmendai-demo-health-json"}\n'
        ).encode(),
    }
    for name, content in render_canary_systemd_units().items():
        files[f"etc/systemd/system/{name}"] = content.encode()
    return files


def _record(path: Path, root: Path) -> CanaryFileRecord:
    data = path.read_bytes()
    return CanaryFileRecord(
        "/" + str(path.relative_to(root)),
        hashlib.sha256(data).hexdigest(),
        len(data),
        "0750" if "/bin/" in str(path) else "0640",
    )


def _manifest_checksum(data: dict[str, Any]) -> str:
    copy = json.loads(json.dumps(data))
    copy["manifest_checksum"] = ""
    return hashlib.sha256(json.dumps(copy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _manifest_from_files(config: DedicatedCanaryConfig, root: Path, audit_sha256: str) -> CanaryManifest:
    records = tuple(
        _record(root / relative, root)
        for relative in sorted(_relative_install_files(config))
        if (root / relative).exists()
    )
    manifest = CanaryManifest(
        SCHEMA_VERSION,
        config.application_id,
        config.canary_identity,
        __version__,
        str(root),
        records,
        audit_sha256,
        "",
    )
    return CanaryManifest(**{**asdict(manifest), "manifest_checksum": _manifest_checksum(asdict(manifest))})


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def install_canary_package(
    config: DedicatedCanaryConfig,
    root: str | Path,
    *,
    apply: bool = False,
    actual_hostname: str | None = None,
    canary_identity: str | None = None,
    live_reviewed: bool = False,
) -> CanaryOperationResult:
    install_root = validate_canary_root(root, live_reviewed=live_reviewed)
    host = validate_host_identity(config, actual_hostname=actual_hostname, canary_identity=canary_identity)
    if not host.accepted:
        raise InstallationValidationError("unverified host rejected")
    files = _relative_install_files(config)
    planned = tuple("/" + item for item in sorted(files))
    conflicts: list[str] = []
    unchanged: list[str] = []
    for relative, content in files.items():
        path = install_root / relative
        if path.exists():
            if path.is_symlink():
                raise InstallationValidationError("symlink escape rejected")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != hashlib.sha256(content).hexdigest():
                conflicts.append("/" + relative)
            else:
                unchanged.append("/" + relative)
    if conflicts:
        raise InstallationConflictError("conflicting existing files block overwrite")
    audit = {
        "schema_version": SCHEMA_VERSION,
        "application_id": config.application_id,
        "action": CanaryAction.INSTALL_APPLY.value if apply else CanaryAction.INSTALL_PREVIEW.value,
        "host": host.actual_hostname,
        "canary_identity_verified": host.accepted,
        "changed": bool(apply),
        "materials_copied": False,
        "notifications_enabled": False,
        "repairs_enabled": False,
        "network_enabled": False,
        "preserved_paths": ["/root/shieldmend_demo.sh"],
    }
    audit_bytes = json.dumps(redact(audit), sort_keys=True).encode()
    if not apply:
        return CanaryOperationResult(
            CanaryAction.INSTALL_PREVIEW,
            True,
            False,
            False,
            host,
            planned,
            (),
            (),
            tuple(unchanged),
            (),
            None,
            redact(audit),
        )
    created: list[str] = []
    for relative, content in files.items():
        path = install_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            created.append("/" + relative)
        path.write_bytes(content)
    audit_path = install_root / "var/lib/shieldmendai/installation" / AUDIT_NAME
    _write_json(audit_path, redact(audit))
    audit_sha = hashlib.sha256(audit_bytes).hexdigest()
    manifest = _manifest_from_files(config, install_root, audit_sha)
    manifest_path = install_root / "var/lib/shieldmendai/installation" / MANIFEST_NAME
    _write_json(manifest_path, safe_canary_dict(manifest))
    return CanaryOperationResult(
        CanaryAction.INSTALL_APPLY,
        False,
        True,
        bool(created),
        host,
        planned,
        tuple(created),
        (),
        tuple(unchanged),
        (),
        manifest,
        redact(audit),
    )


def load_canary_manifest(root: str | Path, *, live_reviewed: bool = False) -> CanaryManifest:
    install_root = validate_canary_root(root, live_reviewed=live_reviewed)
    path = install_root / "var/lib/shieldmendai/installation" / MANIFEST_NAME
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise InstallationValidationError("canary manifest could not be loaded") from None
    checksum = _text(data.get("manifest_checksum"), "manifest_checksum")
    if checksum != _manifest_checksum(data):
        raise InstallationValidationError("canary manifest checksum mismatch")
    files = tuple(
        CanaryFileRecord(
            _text(item.get("path"), "manifest.files.path", path=True),
            _text(item.get("sha256"), "manifest.files.sha256"),
            _integer(item.get("size_bytes"), "manifest.files.size_bytes", 0, 1_000_000_000),
            _text(item.get("mode"), "manifest.files.mode"),
        )
        for item in _list(data.get("files"), "manifest.files")
    )
    return CanaryManifest(
        SCHEMA_VERSION,
        _text(data.get("application_id"), "application_id", identifier=True),
        _text(data.get("canary_identity"), "canary_identity", identifier=True),
        _text(data.get("package_version"), "package_version"),
        _text(data.get("install_root"), "install_root", path=True),
        files,
        _text(data.get("audit_sha256"), "audit_sha256"),
        checksum,
    )


def rollback_canary_package(
    root: str | Path, *, apply: bool = False, live_reviewed: bool = False
) -> CanaryOperationResult:
    install_root = validate_canary_root(root, live_reviewed=live_reviewed)
    manifest = load_canary_manifest(install_root, live_reviewed=live_reviewed)
    conflicts: list[str] = []
    removed: list[str] = []
    preserved: list[str] = []
    for record in manifest.files:
        path = install_root.joinpath(*PurePosixPath(record.path).parts[1:])
        if not path.exists():
            preserved.append(record.path)
            continue
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != record.sha256:
            conflicts.append(record.path)
    if conflicts:
        raise InstallationConflictError("modified file blocks unsafe removal")
    if apply:
        for record in reversed(manifest.files):
            path = install_root.joinpath(*PurePosixPath(record.path).parts[1:])
            if path.exists():
                path.unlink()
                removed.append(record.path)
        for extra in (
            install_root / "var/lib/shieldmendai/installation" / MANIFEST_NAME,
            install_root / "var/lib/shieldmendai/installation" / AUDIT_NAME,
        ):
            if extra.exists() and not extra.is_symlink():
                extra.unlink()
                removed.append("/" + str(extra.relative_to(install_root)))
    return CanaryOperationResult(
        CanaryAction.ROLLBACK_APPLY if apply else CanaryAction.ROLLBACK_PREVIEW,
        not apply,
        apply,
        bool(removed),
        None,
        tuple(item.path for item in manifest.files),
        (),
        tuple(removed),
        tuple(preserved),
        (),
        manifest,
        {
            "action": CanaryAction.ROLLBACK_APPLY.value if apply else CanaryAction.ROLLBACK_PREVIEW.value,
            "removed_only_manifest_owned_files": apply,
            "unknown_files_preserved": True,
            "sanitized": True,
        },
    )


def observe_demo_health(
    config: DedicatedCanaryConfig,
    root: str | Path,
    *,
    observed_at: str,
    live_reviewed: bool = False,
) -> CanaryObservationResult:
    install_root = validate_canary_root(root, live_reviewed=live_reviewed)
    target = config.targets[0]
    health_path = install_root / "var/lib/shieldmendai/demo/health.json"
    healthy = False
    if health_path.exists() and health_path.is_file() and not health_path.is_symlink():
        try:
            payload = json.loads(health_path.read_text(encoding="utf-8"))
            healthy = (
                payload.get("application_id") == config.application_id
                and payload.get("target_id") == target.target_id
                and payload.get("status") == "healthy"
            )
        except (OSError, json.JSONDecodeError):
            healthy = False
    incident_root = install_root / "var/lib/shieldmendai/incidents"
    incident_root.mkdir(parents=True, exist_ok=True)
    store = LocalIncidentStore(incident_root)
    incident_id = f"canary-{target.target_id}"
    records = [item for item in store.list_records() if item.incident_id == incident_id]
    latest = max(records, key=lambda item: item.metadata.record_version) if records else None
    references: list[str] = []
    if not healthy:
        if latest is None:
            created = create_incident_record(
                incident_id=incident_id,
                application_id=config.application_id,
                target_id=target.target_id,
                adapter_type=target.adapter_type,
                category=target.incident_category,
                severity=target.severity,
                confidence=Confidence.DETERMINISTIC,
                summary="Dedicated canary demo target is unhealthy",
                sanitized_description="Read-only canary observed the local demo health artifact as missing or unhealthy.",
                timestamp=observed_at,
                source=IncidentSource.OBSERVATION,
                tags=("phase8", "dedicated_canary", "read_only"),
            )
            store.write(created)
            latest = transition_incident(
                created,
                IncidentStatus.OPEN,
                timestamp=observed_at,
                event_type=IncidentEventType.FINDING_RECORDED,
                reason_code="demo_unhealthy",
                sanitized_message="Dedicated canary unhealthy finding recorded.",
            )
            store.write(latest)
        references.append(incident_id)
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
            timestamp=observed_at,
            event_type=IncidentEventType.VERIFICATION_SUCCEEDED,
            reason_code="manual_demo_recovery_verified",
            sanitized_message="Operator-restored demo health was verified by read-only observation.",
        )
        store.write(resolved)
        references.append(incident_id)
    return CanaryObservationResult(
        CanaryAction.OBSERVE,
        target.target_id,
        ObservationStatus.HEALTHY if healthy else ObservationStatus.UNHEALTHY,
        tuple(references),
        False,
        False,
        False,
        False,
        1,
        "healthy" if healthy else "unhealthy incident recorded without repair",
    )
