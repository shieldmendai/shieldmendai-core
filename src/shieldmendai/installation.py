"""Controlled temporary-root installation and uninstallation simulation."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, TypeVar

import yaml

from . import __version__
from .errors import (
    InstallationConflictError,
    InstallationValidationError,
    UnsafeSandboxError,
)
from .redaction import redact, sanitize_message

SCHEMA_VERSION = "1.0"
MANIFEST_NAME = "installation-manifest.json"
_T = TypeVar("_T")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_MODE = re.compile(r"^0[0-7]{3}$")
_PRIVATE_PARTS = ("root", "new" + "basebot")
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_PRODUCTION_ROOTS = tuple(Path(item) for item in ("/", "/etc", "/usr", "/var", "/opt", "/home", "/root"))
_SENSITIVE = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:token|password|api[_-]?key|secret)\s*[:=]|"
    r"[a-z][a-z0-9+.-]*://[^/\s]+@)",
    re.IGNORECASE,
)


class InstallationPathKind(str, Enum):
    INSTALL_PREFIX = "install_prefix"
    CONFIGURATION = "configuration"
    STATE = "state"
    INCIDENT = "incident"
    LOG = "log"
    RUNTIME = "runtime"
    UNIT = "unit"


@dataclass(frozen=True)
class InstallationTarget:
    platform: str
    architecture: str
    simulation_only: bool = True


@dataclass(frozen=True)
class InstallationPath:
    kind: InstallationPathKind
    production_path: str
    sandbox_path: str
    created_by_installer: bool = True


@dataclass(frozen=True)
class InstallationFile:
    file_id: str
    production_path: str
    sandbox_path: str
    sha256: str
    size_bytes: int
    mode: str
    owner: str
    group: str
    generated: bool = True


@dataclass(frozen=True)
class ServiceUserPlan:
    user: str
    group: str
    interactive_shell: bool
    home_directory: str | None
    sudo_allowed: bool
    run_as_root: bool
    read_paths: tuple[str, ...]
    write_paths: tuple[str, ...]
    prohibited_permissions: tuple[str, ...]
    additional_scope_requires_review: bool = True


@dataclass(frozen=True)
class PermissionPlan:
    path: str
    mode: str
    reason: str
    modeled_only: bool = True


@dataclass(frozen=True)
class OwnershipPlan:
    path: str
    owner: str
    group: str
    modeled_only: bool = True


@dataclass(frozen=True)
class ConfigurationBootstrapPlan:
    path: str
    schema_version: str
    local_only: bool
    read_only: bool
    repairs_enabled: bool
    notifications_enabled: bool
    network_enabled: bool
    secret_reference_placeholders_only: bool


@dataclass(frozen=True)
class UnitTemplatePlan:
    name: str
    unit_type: str
    path: str
    enabled: bool
    started: bool
    repair_execution: bool
    notification_delivery: bool
    network_dependency: bool


@dataclass(frozen=True)
class InstallationPrecondition:
    name: str
    satisfied: bool
    detail: str


@dataclass(frozen=True)
class InstallationValidationResult:
    valid: bool
    checks: tuple[InstallationPrecondition, ...]
    conflicts: tuple[str, ...] = ()


@dataclass(frozen=True)
class InstallationAuditEvent:
    event_id: str
    installation_id: str
    timestamp: str
    event_type: str
    detail: str
    sandbox_only: bool = True
    host_changed: bool = False
    production_installation_affected: bool = False


@dataclass(frozen=True)
class InstallationPlan:
    installation_id: str
    schema_version: str
    package_version: str
    target: InstallationTarget
    sandbox_root: str | None
    service_user: ServiceUserPlan
    paths: tuple[InstallationPath, ...]
    executable_reference: str
    configuration_files: tuple[str, ...]
    unit_templates: tuple[UnitTemplatePlan, ...]
    permission_plan: tuple[PermissionPlan, ...]
    ownership_plan: tuple[OwnershipPlan, ...]
    bootstrap: ConfigurationBootstrapPlan
    preconditions: tuple[InstallationPrecondition, ...]
    uninstall_preview_default: bool
    simulation: bool
    created_at: str


@dataclass(frozen=True)
class InstallationManifest:
    schema_version: str
    installation_id: str
    package_version: str
    sandbox_root: str
    created_at: str
    updated_at: str
    service_user: ServiceUserPlan
    paths: tuple[InstallationPath, ...]
    files: tuple[InstallationFile, ...]
    permission_plan: tuple[PermissionPlan, ...]
    ownership_plan: tuple[OwnershipPlan, ...]
    audit_events: tuple[InstallationAuditEvent, ...]
    manifest_checksum: str
    simulation: bool = True


@dataclass(frozen=True)
class InstallationSimulationResult:
    manifest: InstallationManifest
    validation: InstallationValidationResult
    created_files: tuple[str, ...]
    unchanged_files: tuple[str, ...]
    audit_events: tuple[InstallationAuditEvent, ...]
    idempotent: bool
    production_installation_performed: bool = False
    simulation: bool = True


@dataclass(frozen=True)
class UninstallationPlan:
    installation_id: str
    sandbox_root: str
    preview_only: bool
    remove_generated_fixtures: bool
    recorded_files: tuple[str, ...]
    recorded_directories: tuple[str, ...]
    conflicts: tuple[str, ...]
    unknown_files: tuple[str, ...]
    production_installation_targeted: bool = False


@dataclass(frozen=True)
class UninstallationSimulationResult:
    plan: UninstallationPlan
    removed_files: tuple[str, ...]
    removed_directories: tuple[str, ...]
    preserved_unknown_files: tuple[str, ...]
    conflicts: tuple[str, ...]
    audit_events: tuple[InstallationAuditEvent, ...]
    preview_only: bool
    production_installation_removed: bool = False
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
        raise InstallationValidationError(f"{location} must be a mapping")
    return value


def _reject_unknown(data: dict[str, Any], allowed: set[str], location: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise InstallationValidationError(f"{location} contains unknown fields: {', '.join(unknown)}")


def _text(value: Any, location: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InstallationValidationError(f"{location} must be a non-empty string")
    result = sanitize_message(value.strip())
    if _SENSITIVE.search(result):
        raise InstallationValidationError(f"{location} contains credential-like data")
    if identifier and not _ID.fullmatch(result):
        raise InstallationValidationError(f"{location} contains unsupported characters")
    if "*" in result:
        raise InstallationValidationError(f"{location} must not contain wildcards")
    return result


def _boolean(value: Any, location: str) -> bool:
    if not isinstance(value, bool):
        raise InstallationValidationError(f"{location} must be true or false")
    return value


def _timestamp(value: Any, location: str) -> str:
    result = _text(value, location)
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError:
        raise InstallationValidationError(f"{location} must be an ISO-8601 timestamp") from None
    if parsed.tzinfo is None:
        raise InstallationValidationError(f"{location} must include a timezone")
    return result


def _production_path(value: Any, location: str) -> str:
    result = _text(value, location)
    path = PurePosixPath(result)
    if not path.is_absolute() or ".." in path.parts:
        raise InstallationValidationError(f"{location} must be an absolute normalized future path")
    return str(path)


def validate_sandbox_root(root: str | Path) -> Path:
    candidate = Path(root)
    if not candidate.is_absolute():
        raise UnsafeSandboxError("sandbox root must be explicitly provided as an absolute path")
    if ".." in candidate.parts:
        raise UnsafeSandboxError("sandbox root cannot contain path traversal")
    lowered = tuple(part.lower() for part in candidate.parts)
    if lowered[-2:] == _PRIVATE_PARTS:
        raise UnsafeSandboxError("sandbox root is prohibited")
    if any(candidate == path for path in _PRODUCTION_ROOTS):
        raise UnsafeSandboxError("production root is prohibited")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise UnsafeSandboxError("sandbox root must already exist") from None
    temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
    if candidate.is_symlink() or candidate.absolute() != resolved:
        raise UnsafeSandboxError("sandbox root cannot be a symlink or traverse symlinks")
    if resolved == temporary_root:
        raise UnsafeSandboxError("temporary directory root itself is prohibited")
    if not resolved.is_dir() or not resolved.is_relative_to(temporary_root):
        raise UnsafeSandboxError("sandbox root must be beneath the operating system temporary directory")
    if resolved == _REPOSITORY_ROOT or resolved.is_relative_to(_REPOSITORY_ROOT):
        raise UnsafeSandboxError("repository directories cannot be installation sandboxes")
    return resolved


def _sandbox_path(root: Path, production_path: str) -> Path:
    future = PurePosixPath(production_path)
    if not future.is_absolute() or ".." in future.parts:
        raise UnsafeSandboxError("future path is not safe to map")
    target = root.joinpath(*future.parts[1:])
    parent = target.parent
    existing = parent
    while not existing.exists() and existing != root:
        existing = existing.parent
    resolved_parent = existing.resolve(strict=True)
    if not resolved_parent.is_relative_to(root):
        raise UnsafeSandboxError("mapped path escapes sandbox root")
    for item in target.parents:
        if item == root:
            break
        if item.exists() and item.is_symlink():
            raise UnsafeSandboxError("mapped path cannot traverse symlinks")
    if target.exists() and target.is_symlink():
        raise UnsafeSandboxError("mapped path cannot be a symlink")
    return target


def _service_user() -> ServiceUserPlan:
    return ServiceUserPlan(
        user="shieldmendai",
        group="shieldmendai",
        interactive_shell=False,
        home_directory=None,
        sudo_allowed=False,
        run_as_root=False,
        read_paths=(
            "/etc/shieldmendai",
            "/opt/shieldmendai",
            "explicitly allowlisted target fixture paths",
        ),
        write_paths=(
            "/var/lib/shieldmendai",
            "/var/lib/shieldmendai/incidents",
            "/var/log/shieldmendai",
            "/run/shieldmendai",
        ),
        prohibited_permissions=(
            "root ownership",
            "sudo",
            "interactive login",
            "unrestricted filesystem access",
            "unrestricted process access",
            "unrestricted network access",
        ),
    )


def _validate_service_user(plan: ServiceUserPlan) -> None:
    if plan.user == "root" or plan.group == "root" or plan.run_as_root:
        raise InstallationValidationError("service user must not run as root")
    if plan.sudo_allowed:
        raise InstallationValidationError("service user must not have sudo")
    if plan.interactive_shell:
        raise InstallationValidationError("service user must be noninteractive")


def _unit_templates() -> dict[str, str]:
    common = """[Unit]
Description={description}
After=local-fs.target

[Service]
Type=oneshot
User=shieldmendai
Group=shieldmendai
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/var/lib/shieldmendai /var/log/shieldmendai /run/shieldmendai
ExecStart=/opt/shieldmendai/bin/shieldmendai {command} /etc/shieldmendai/{config}
"""
    return {
        "shieldmendai-observer.service": common.format(
            description="ShieldMendAi read-only observer",
            command="simulate-linux-pilot",
            config="pilot.yaml",
        ),
        "shieldmendai-observer.timer": """[Unit]
Description=Schedule ShieldMendAi read-only observation

[Timer]
OnBootSec=5m
OnUnitActiveSec=5m
Persistent=false
Unit=shieldmendai-observer.service

[Install]
WantedBy=timers.target
""",
        "shieldmendai-incident-maintenance.service": common.format(
            description="ShieldMendAi incident maintenance preview",
            command="preview-retention",
            config="retention.yaml",
        ),
        "shieldmendai-incident-maintenance.timer": """[Unit]
Description=Schedule ShieldMendAi incident maintenance preview

[Timer]
OnCalendar=daily
Persistent=false
Unit=shieldmendai-incident-maintenance.service

[Install]
WantedBy=timers.target
""",
    }


def render_systemd_units() -> dict[str, str]:
    return dict(_unit_templates())


def parse_installation_plan(data: Any) -> InstallationPlan:
    root = _mapping(data, "installation")
    _reject_unknown(
        root,
        {
            "schema_version",
            "installation_id",
            "package_version",
            "target_platform",
            "target_architecture",
            "created_at",
            "paths",
            "executable_reference",
        },
        "installation",
    )
    schema = _text(root.get("schema_version"), "installation.schema_version")
    if schema != SCHEMA_VERSION:
        raise InstallationValidationError("unknown installation schema version")
    installation_id = _text(
        root.get("installation_id"), "installation.installation_id", identifier=True
    )
    package_version = _text(
        root.get("package_version", __version__), "installation.package_version"
    )
    paths_data = _mapping(root.get("paths"), "installation.paths")
    expected_paths = {
        "install_prefix": "/opt/shieldmendai",
        "configuration_directory": "/etc/shieldmendai",
        "state_directory": "/var/lib/shieldmendai",
        "incident_directory": "/var/lib/shieldmendai/incidents",
        "log_directory": "/var/log/shieldmendai",
        "runtime_directory": "/run/shieldmendai",
        "unit_directory": "/etc/systemd/system",
    }
    _reject_unknown(paths_data, set(expected_paths), "installation.paths")
    production_paths: dict[str, str] = {}
    for key, expected in expected_paths.items():
        value = _production_path(paths_data.get(key, expected), f"installation.paths.{key}")
        if value != expected:
            raise InstallationValidationError(
                f"installation.paths.{key} must use the reviewed future layout"
            )
        production_paths[key] = value
    service_user = _service_user()
    _validate_service_user(service_user)
    permission_plan = (
        PermissionPlan(production_paths["configuration_directory"], "0750", "configuration is not public"),
        PermissionPlan(production_paths["state_directory"], "0750", "state is service-controlled"),
        PermissionPlan(production_paths["incident_directory"], "0750", "incident records are private"),
        PermissionPlan(production_paths["log_directory"], "0750", "logs are service-controlled"),
        PermissionPlan(production_paths["runtime_directory"], "0750", "runtime data is ephemeral"),
        PermissionPlan(f"{production_paths['configuration_directory']}/pilot.yaml", "0640", "configuration is read-only to the service"),
    )
    if any(item.mode.endswith(("2", "3", "6", "7")) for item in permission_plan):
        raise InstallationValidationError("permission plan must not be world-writable")
    ownership_plan = tuple(
        OwnershipPlan(path, "shieldmendai", "shieldmendai")
        for path in (
            production_paths["configuration_directory"],
            production_paths["state_directory"],
            production_paths["incident_directory"],
            production_paths["log_directory"],
            production_paths["runtime_directory"],
        )
    )
    paths = (
        InstallationPath(InstallationPathKind.INSTALL_PREFIX, production_paths["install_prefix"], ""),
        InstallationPath(InstallationPathKind.CONFIGURATION, production_paths["configuration_directory"], ""),
        InstallationPath(InstallationPathKind.STATE, production_paths["state_directory"], ""),
        InstallationPath(InstallationPathKind.INCIDENT, production_paths["incident_directory"], ""),
        InstallationPath(InstallationPathKind.LOG, production_paths["log_directory"], ""),
        InstallationPath(InstallationPathKind.RUNTIME, production_paths["runtime_directory"], ""),
        InstallationPath(InstallationPathKind.UNIT, production_paths["unit_directory"], ""),
    )
    units = tuple(
        UnitTemplatePlan(
            name=name,
            unit_type=name.rsplit(".", 1)[-1],
            path=f"{production_paths['unit_directory']}/{name}",
            enabled=False,
            started=False,
            repair_execution=False,
            notification_delivery=False,
            network_dependency=False,
        )
        for name in sorted(_unit_templates())
    )
    bootstrap_path = f"{production_paths['configuration_directory']}/pilot.yaml"
    return InstallationPlan(
        installation_id=installation_id,
        schema_version=schema,
        package_version=package_version,
        target=InstallationTarget(
            _text(root.get("target_platform", "linux"), "installation.target_platform", identifier=True),
            _text(root.get("target_architecture", "generic"), "installation.target_architecture", identifier=True),
        ),
        sandbox_root=None,
        service_user=service_user,
        paths=paths,
        executable_reference=_production_path(
            root.get("executable_reference", "/opt/shieldmendai/bin/shieldmendai"),
            "installation.executable_reference",
        ),
        configuration_files=(bootstrap_path,),
        unit_templates=units,
        permission_plan=permission_plan,
        ownership_plan=ownership_plan,
        bootstrap=ConfigurationBootstrapPlan(
            bootstrap_path, SCHEMA_VERSION, True, True, False, False, False, True
        ),
        preconditions=(
            InstallationPrecondition("simulation_only", True, "No production installation is available."),
            InstallationPrecondition("service_user_modeled_only", True, "No user or group will be created."),
            InstallationPrecondition("systemd_templates_only", True, "Units will not be installed or started."),
        ),
        uninstall_preview_default=True,
        simulation=True,
        created_at=_timestamp(root.get("created_at"), "installation.created_at"),
    )


def load_installation_plan(path: str | Path) -> InstallationPlan:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        raise InstallationValidationError("installation plan could not be loaded") from None
    return parse_installation_plan(data)


def _bootstrap_config(plan: InstallationPlan, root: Path) -> str:
    mapped = {item.kind: str(_sandbox_path(root, item.production_path)) for item in plan.paths}
    data = {
        "schema_version": SCHEMA_VERSION,
        "application_id": "shieldmendai-pilot",
        "environment_label": "sandbox",
        "local_only": True,
        "read_only": True,
        "observation_enabled": True,
        "repairs_enabled": False,
        "notification_delivery_enabled": False,
        "network_access_enabled": False,
        "automatic_target_discovery": False,
        "pilot_mode": "fixture_only",
        "incident_store_path": mapped[InstallationPathKind.INCIDENT],
        "state_store_path": mapped[InstallationPathKind.STATE],
        "log_level": "INFO",
        "observation_interval_seconds": 300,
        "target_allowlist": ["fixture-service"],
        "adapters": [
            {
                "adapter_type": "systemd_service",
                "enabled": True,
                "fixture_backed": True,
                "production_enabled": False,
            }
        ],
        "secret_references": [],
    }
    return yaml.safe_dump(data, sort_keys=True)


def _artifact_payload() -> bytes:
    return (
        "#!/usr/bin/env python3\n"
        "# Public ShieldMendAi package entrypoint placeholder for sandbox simulation.\n"
        "raise SystemExit('sandbox artifact only; use the installed Python package CLI')\n"
    ).encode()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest_checksum(data: dict[str, Any]) -> str:
    clean = dict(data)
    clean["manifest_checksum"] = ""
    payload = json.dumps(clean, sort_keys=True, separators=(",", ":")).encode()
    return _sha256(payload)


def _with_manifest_checksum(manifest: InstallationManifest) -> InstallationManifest:
    clean = replace(manifest, manifest_checksum="")
    return replace(clean, manifest_checksum=_manifest_checksum(_primitive(clean)))


def parse_installation_manifest(data: Any) -> InstallationManifest:
    root = _mapping(data, "manifest")
    required = {
        "schema_version", "installation_id", "package_version", "sandbox_root",
        "created_at", "updated_at", "service_user", "paths", "files",
        "permission_plan", "ownership_plan", "audit_events", "manifest_checksum", "simulation",
    }
    _reject_unknown(root, required, "manifest")
    if set(root) != required:
        raise InstallationValidationError("manifest is missing required fields")
    if root["schema_version"] != SCHEMA_VERSION:
        raise InstallationValidationError("unknown installation manifest schema")
    service = ServiceUserPlan(**_mapping(root["service_user"], "manifest.service_user"))
    _validate_service_user(service)
    paths = tuple(
        InstallationPath(
            InstallationPathKind(item["kind"]),
            _production_path(item["production_path"], "manifest.paths.production_path"),
            _text(item["sandbox_path"], "manifest.paths.sandbox_path"),
            _boolean(item["created_by_installer"], "manifest.paths.created_by_installer"),
        )
        for item in root["paths"]
    )
    files = tuple(InstallationFile(**item) for item in root["files"])
    permissions = tuple(PermissionPlan(**item) for item in root["permission_plan"])
    ownership = tuple(OwnershipPlan(**item) for item in root["ownership_plan"])
    events = tuple(InstallationAuditEvent(**item) for item in root["audit_events"])
    manifest = InstallationManifest(
        SCHEMA_VERSION,
        _text(root["installation_id"], "manifest.installation_id", identifier=True),
        _text(root["package_version"], "manifest.package_version"),
        _text(root["sandbox_root"], "manifest.sandbox_root"),
        _timestamp(root["created_at"], "manifest.created_at"),
        _timestamp(root["updated_at"], "manifest.updated_at"),
        service,
        paths,
        files,
        permissions,
        ownership,
        events,
        _text(root["manifest_checksum"], "manifest.manifest_checksum"),
        _boolean(root["simulation"], "manifest.simulation"),
    )
    if not manifest.simulation:
        raise InstallationValidationError("production installation manifests are unavailable")
    if _manifest_checksum(_primitive(manifest)) != manifest.manifest_checksum:
        raise InstallationValidationError("installation manifest checksum mismatch")
    return manifest


def load_installation_manifest(root: str | Path) -> InstallationManifest:
    sandbox = validate_sandbox_root(root)
    path = _sandbox_path(sandbox, f"/var/lib/shieldmendai/{MANIFEST_NAME}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise InstallationValidationError("installation manifest could not be loaded") from None
    manifest = parse_installation_manifest(data)
    if Path(manifest.sandbox_root) != sandbox:
        raise InstallationValidationError("installation manifest sandbox root mismatch")
    return manifest


def _safe_write(path: Path, content: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise UnsafeSandboxError("installation file cannot be a symlink")
    if path.exists():
        current = path.read_bytes()
        if current != content:
            raise InstallationConflictError(f"installation conflict at {path.name}")
        return "unchanged"
    path.write_bytes(content)
    return "created"


def simulate_install(plan: InstallationPlan, sandbox_root: str | Path) -> InstallationSimulationResult:
    root = validate_sandbox_root(sandbox_root)
    mapped_paths = tuple(
        replace(item, sandbox_path=str(_sandbox_path(root, item.production_path)))
        for item in plan.paths
    )
    for item in mapped_paths:
        _sandbox_path(root, item.production_path).mkdir(parents=True, exist_ok=True)
    contents: dict[str, bytes] = {
        "/opt/shieldmendai/bin/shieldmendai": _artifact_payload(),
        "/etc/shieldmendai/pilot.yaml": _bootstrap_config(plan, root).encode(),
    }
    for name, text in _unit_templates().items():
        contents[f"/etc/systemd/system/{name}"] = text.encode()
    created: list[str] = []
    unchanged: list[str] = []
    files: list[InstallationFile] = []
    for index, production_path in enumerate(sorted(contents), start=1):
        content = contents[production_path]
        target = _sandbox_path(root, production_path)
        status = _safe_write(target, content)
        (created if status == "created" else unchanged).append(str(target))
        mode = "0750" if production_path.endswith("/shieldmendai") else "0640"
        files.append(
            InstallationFile(
                f"installation-file-{index}",
                production_path,
                str(target),
                _sha256(content),
                len(content),
                mode,
                "shieldmendai",
                "shieldmendai",
            )
        )
    prior: InstallationManifest | None = None
    manifest_path = _sandbox_path(root, f"/var/lib/shieldmendai/{MANIFEST_NAME}")
    if manifest_path.exists():
        prior = load_installation_manifest(root)
        if prior.installation_id != plan.installation_id:
            raise InstallationConflictError("sandbox contains a different installation ID")
        if tuple((item.production_path, item.sha256) for item in prior.files) != tuple(
            (item.production_path, item.sha256) for item in files
        ):
            raise InstallationConflictError("sandbox manifest conflicts with installation plan")
    event = InstallationAuditEvent(
        f"{plan.installation_id}.install.{1 if prior is None else len(prior.audit_events) + 1}",
        plan.installation_id,
        plan.created_at,
        "sandbox_installation_created" if prior is None else "sandbox_installation_verified",
        "Sandbox installation simulated; no host installation occurred.",
    )
    manifest = _with_manifest_checksum(
        InstallationManifest(
            SCHEMA_VERSION,
            plan.installation_id,
            plan.package_version,
            str(root),
            prior.created_at if prior else plan.created_at,
            plan.created_at,
            plan.service_user,
            mapped_paths,
            tuple(files),
            plan.permission_plan,
            plan.ownership_plan,
            (prior.audit_events if prior else ()) + (event,),
            "",
        )
    )
    payload = json.dumps(_primitive(manifest), indent=2, sort_keys=True).encode() + b"\n"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    if manifest_path.is_symlink():
        raise UnsafeSandboxError("installation manifest cannot be a symlink")
    manifest_path.write_bytes(payload)
    validation = inspect_installation(root)
    return InstallationSimulationResult(
        manifest,
        validation,
        tuple(created),
        tuple(unchanged),
        (event,),
        prior is not None and not created,
    )


def inspect_installation(root: str | Path) -> InstallationValidationResult:
    sandbox = validate_sandbox_root(root)
    manifest = load_installation_manifest(sandbox)
    checks: list[InstallationPrecondition] = []
    conflicts: list[str] = []
    for item in manifest.files:
        path = Path(item.sandbox_path)
        safe = _sandbox_path(sandbox, item.production_path)
        if path != safe or not path.exists() or path.is_symlink():
            conflicts.append(item.production_path)
            continue
        if _sha256(path.read_bytes()) != item.sha256:
            conflicts.append(item.production_path)
    checks.append(InstallationPrecondition("manifest_checksum", True, "Manifest checksum is valid."))
    checks.append(
        InstallationPrecondition(
            "recorded_files", not conflicts, "All recorded files match." if not conflicts else "Recorded file conflict detected."
        )
    )
    return InstallationValidationResult(not conflicts, tuple(checks), tuple(sorted(conflicts)))


def plan_uninstall(root: str | Path, *, preview_only: bool = True, remove_generated_fixtures: bool = False) -> UninstallationPlan:
    sandbox = validate_sandbox_root(root)
    manifest = load_installation_manifest(sandbox)
    conflicts: list[str] = []
    known = {Path(item.sandbox_path) for item in manifest.files}
    manifest_path = _sandbox_path(sandbox, f"/var/lib/shieldmendai/{MANIFEST_NAME}")
    known.add(manifest_path)
    for item in manifest.files:
        path = Path(item.sandbox_path)
        if path.exists() and (path.is_symlink() or _sha256(path.read_bytes()) != item.sha256):
            conflicts.append(str(path))
    unknown = tuple(
        str(path)
        for path in sorted(sandbox.rglob("*"))
        if path.is_file() and path not in known
    )
    return UninstallationPlan(
        manifest.installation_id,
        str(sandbox),
        preview_only,
        remove_generated_fixtures,
        tuple(sorted(str(path) for path in known)),
        tuple(
            sorted(
                (item.sandbox_path for item in manifest.paths),
                key=lambda value: (-len(Path(value).parts), value),
            )
        ),
        tuple(sorted(conflicts)),
        unknown,
    )


def simulate_uninstall(
    root: str | Path,
    *,
    preview_only: bool = True,
    remove_generated_fixtures: bool = False,
) -> UninstallationSimulationResult:
    manifest = load_installation_manifest(root)
    plan = plan_uninstall(
        root,
        preview_only=preview_only,
        remove_generated_fixtures=remove_generated_fixtures,
    )
    if not preview_only and not remove_generated_fixtures:
        raise InstallationValidationError(
            "fixture removal requires an explicit remove_generated_fixtures flag"
        )
    if plan.conflicts and not preview_only:
        raise InstallationConflictError("modified installed files block fixture removal")
    removed_files: list[str] = []
    removed_directories: list[str] = []
    if not preview_only:
        for value in plan.recorded_files:
            path = Path(value)
            if path.exists():
                if path.is_symlink():
                    raise UnsafeSandboxError("uninstallation cannot follow symlinks")
                path.unlink()
                removed_files.append(value)
        for value in plan.recorded_directories:
            path = Path(value)
            if path.exists() and path.is_dir() and not path.is_symlink():
                try:
                    path.rmdir()
                except OSError:
                    pass
                else:
                    removed_directories.append(value)
        for parent in sorted(
            {path.parent for path in map(Path, plan.recorded_files)},
            key=lambda value: -len(value.parts),
        ):
            if parent == Path(plan.sandbox_root):
                continue
            try:
                parent.rmdir()
            except OSError:
                pass
    event = InstallationAuditEvent(
        f"{plan.installation_id}.uninstall.preview" if preview_only else f"{plan.installation_id}.uninstall.fixture",
        plan.installation_id,
        manifest.updated_at,
        "uninstall_preview" if preview_only else "sandbox_fixture_uninstalled",
        "No production installation was removed.",
    )
    return UninstallationSimulationResult(
        plan,
        tuple(removed_files),
        tuple(removed_directories),
        plan.unknown_files,
        plan.conflicts,
        (event,),
        preview_only,
    )


def safe_installation_dict(value: Any) -> dict[str, Any] | list[Any]:
    return redact(_primitive(value))
