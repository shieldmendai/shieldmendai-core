"""Typed configuration loading and validation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable, TypeVar
from urllib.parse import urlsplit

import yaml

from .errors import ConfigurationError
from .models import (
    AdapterType,
    GlobalSettings,
    NotificationChannel,
    NotificationChannelType,
    NotificationPolicy,
    PolicyMode,
    RepairActionCategory,
    RepairPolicy,
    Severity,
    ShieldMendAiConfig,
    Target,
)
_T = TypeVar("_T")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.@-]*\.(service|timer)$")
_HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_FORBIDDEN_PATH_FRAGMENT = "/root/" + "newbasebot"
_FORBIDDEN_UNIT_PREFIX = "new" + "base-"
_DIRECT_SECRET_KEYS = {
    "token",
    "password",
    "secret",
    "api_key",
    "private_key",
    "authorization",
    "chat_id",
    "signing_secret",
    "account_id",
}


def _mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{location} must be a mapping")
    return value


def _list(value: Any, location: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigurationError(f"{location} must be a list")
    return value


def _text(value: Any, location: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{location} must be a non-empty string")
    result = value.strip()
    if _FORBIDDEN_PATH_FRAGMENT in result or _FORBIDDEN_UNIT_PREFIX in result:
        raise ConfigurationError(f"{location} contains a prohibited private reference")
    if identifier and not _ID_RE.fullmatch(result):
        raise ConfigurationError(f"{location} contains unsupported characters")
    return result


def _integer(
    value: Any,
    location: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{location} must be an integer")
    if value < minimum or maximum is not None and value > maximum:
        limit = f" between {minimum} and {maximum}" if maximum is not None else f" >= {minimum}"
        raise ConfigurationError(f"{location} must be{limit}")
    return value


def _boolean(value: Any, location: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{location} must be true or false")
    return value


def _enum(enum_type: type[_T], value: Any, location: str) -> _T:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        allowed = ", ".join(item.value for item in enum_type)  # type: ignore[attr-defined]
        raise ConfigurationError(f"{location} must be one of: {allowed}") from None


def _unique_ids(items: Iterable[Any], location: str) -> None:
    seen: set[str] = set()
    for item in items:
        identifier = item.id
        if identifier in seen:
            raise ConfigurationError(f"{location} contains duplicate id '{identifier}'")
        seen.add(identifier)


def _reject_direct_secrets(value: Any, location: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in _DIRECT_SECRET_KEYS and item not in (None, ""):
                raise ConfigurationError(
                    f"{location}.{key} must use an environment-reference field, not a direct value"
                )
            _reject_direct_secrets(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_direct_secrets(item, f"{location}[{index}]")
    elif isinstance(value, str):
        if _FORBIDDEN_PATH_FRAGMENT in value or _FORBIDDEN_UNIT_PREFIX in value:
            raise ConfigurationError(f"{location} contains a prohibited private reference")


def _env_reference(settings: dict[str, Any], key: str, location: str, *, required: bool = True) -> None:
    value = settings.get(key)
    if value is None and not required:
        return
    text = _text(value, f"{location}.{key}")
    if not _ENV_RE.fullmatch(text):
        raise ConfigurationError(f"{location}.{key} must be an environment variable name")


def _parse_global(data: dict[str, Any]) -> GlobalSettings:
    location = "global"
    policy = _enum(PolicyMode, data.get("default_policy_mode"), f"{location}.default_policy_mode")
    poll = _integer(data.get("poll_interval_seconds"), f"{location}.poll_interval_seconds")
    if poll == 0:
        raise ConfigurationError("global.poll_interval_seconds must be greater than zero")
    verification = _integer(
        data.get("default_verification_delay_seconds"),
        f"{location}.default_verification_delay_seconds",
    )
    log_level = _text(data.get("log_level"), f"{location}.log_level").upper()
    if log_level not in _LOG_LEVELS:
        raise ConfigurationError(f"{location}.log_level is invalid")
    dry_run = _boolean(data.get("dry_run"), f"{location}.dry_run")
    if not dry_run:
        raise ConfigurationError("global.dry_run must be true in the Phase 2 framework")
    return GlobalSettings(
        schema_version=_text(data.get("schema_version"), f"{location}.schema_version"),
        installation_name=_text(data.get("installation_name"), f"{location}.installation_name"),
        application_name=_text(data.get("application_name"), f"{location}.application_name"),
        environment=_text(data.get("environment"), f"{location}.environment"),
        dry_run=dry_run,
        poll_interval_seconds=poll,
        incident_directory=_text(data.get("incident_directory"), f"{location}.incident_directory"),
        log_level=log_level,
        default_policy_mode=policy,
        default_retry_limit=_integer(
            data.get("default_retry_limit"), f"{location}.default_retry_limit", maximum=100
        ),
        default_cooldown_seconds=_integer(
            data.get("default_cooldown_seconds"), f"{location}.default_cooldown_seconds"
        ),
        default_verification_delay_seconds=verification,
    )


def _parse_repair_policy(data: Any, index: int) -> RepairPolicy:
    item = _mapping(data, f"repair_policies[{index}]")
    location = f"repair_policies[{index}]"
    allowed = tuple(
        _enum(RepairActionCategory, action, f"{location}.allowed_actions")
        for action in _list(item.get("allowed_actions"), f"{location}.allowed_actions")
    )
    if len(allowed) != len(set(allowed)):
        raise ConfigurationError(f"{location}.allowed_actions contains duplicate entries")
    return RepairPolicy(
        id=_text(item.get("id"), f"{location}.id", identifier=True),
        mode=_enum(PolicyMode, item.get("mode"), f"{location}.mode"),
        allowed_actions=allowed,
        retry_limit=(
            _integer(item["retry_limit"], f"{location}.retry_limit", maximum=100)
            if "retry_limit" in item
            else None
        ),
        cooldown_seconds=(
            _integer(item["cooldown_seconds"], f"{location}.cooldown_seconds")
            if "cooldown_seconds" in item
            else None
        ),
        verification_delay_seconds=(
            _integer(item["verification_delay_seconds"], f"{location}.verification_delay_seconds")
            if "verification_delay_seconds" in item
            else None
        ),
        require_pre_repair_evidence=_boolean(
            item.get("require_pre_repair_evidence", True),
            f"{location}.require_pre_repair_evidence",
        ),
        require_verification=_boolean(
            item.get("require_verification", True), f"{location}.require_verification"
        ),
        rollback_on_verification_failure=_boolean(
            item.get("rollback_on_verification_failure", True),
            f"{location}.rollback_on_verification_failure",
        ),
    )


def _validate_notification_settings(
    channel_type: NotificationChannelType,
    settings: dict[str, Any],
    location: str,
) -> None:
    if channel_type is NotificationChannelType.TELEGRAM:
        _env_reference(settings, "token_env", location)
        _env_reference(settings, "chat_id_env", location)
    elif channel_type is NotificationChannelType.EMAIL:
        _text(settings.get("provider_type"), f"{location}.provider_type")
        _text(settings.get("host"), f"{location}.host")
        _env_reference(settings, "username_env", location)
        _env_reference(settings, "password_env", location)
        _text(settings.get("from_address"), f"{location}.from_address")
        recipients = _list(settings.get("recipients"), f"{location}.recipients")
        if not recipients:
            raise ConfigurationError(f"{location}.recipients must not be empty")
        for index, recipient in enumerate(recipients):
            _text(recipient, f"{location}.recipients[{index}]")
    elif channel_type is NotificationChannelType.SMS:
        _text(settings.get("provider_name"), f"{location}.provider_name")
        _env_reference(settings, "account_id_env", location)
        _env_reference(settings, "token_env", location)
        _env_reference(settings, "from_number_env", location)
        recipients = _list(settings.get("recipient_envs"), f"{location}.recipient_envs")
        if not recipients:
            raise ConfigurationError(f"{location}.recipient_envs must not be empty")
        for index, reference in enumerate(recipients):
            if not _ENV_RE.fullmatch(_text(reference, f"{location}.recipient_envs[{index}]")):
                raise ConfigurationError(
                    f"{location}.recipient_envs[{index}] must be an environment variable name"
                )
    elif channel_type is NotificationChannelType.WEBHOOK:
        _env_reference(settings, "url_env", location)
        _env_reference(settings, "signing_secret_env", location, required=False)
        _integer(settings.get("timeout_seconds"), f"{location}.timeout_seconds", minimum=1)
    elif channel_type is NotificationChannelType.LOCAL_FILE:
        _text(settings.get("directory"), f"{location}.directory")


def _parse_notification_channel(data: Any, index: int) -> NotificationChannel:
    item = _mapping(data, f"notification_channels[{index}]")
    location = f"notification_channels[{index}]"
    channel_type = _enum(
        NotificationChannelType, item.get("type"), f"{location}.type"
    )
    settings = _mapping(item.get("settings", {}), f"{location}.settings")
    _reject_direct_secrets(settings, f"{location}.settings")
    _validate_notification_settings(channel_type, settings, f"{location}.settings")
    severities = tuple(
        _enum(Severity, severity, f"{location}.severities")
        for severity in _list(item.get("severities"), f"{location}.severities")
    )
    if not severities:
        raise ConfigurationError(f"{location}.severities must not be empty")
    return NotificationChannel(
        id=_text(item.get("id"), f"{location}.id", identifier=True),
        channel_type=channel_type,
        enabled=_boolean(item.get("enabled", True), f"{location}.enabled"),
        severities=severities,
        retry_limit=_integer(item.get("retry_limit", 0), f"{location}.retry_limit", maximum=100),
        settings=settings,
    )


def _parse_notification_policy(data: Any, index: int) -> NotificationPolicy:
    item = _mapping(data, f"notification_policies[{index}]")
    location = f"notification_policies[{index}]"
    channels = tuple(
        _text(value, f"{location}.channels", identifier=True)
        for value in _list(item.get("channels"), f"{location}.channels")
    )
    return NotificationPolicy(
        id=_text(item.get("id"), f"{location}.id", identifier=True),
        channels=channels,
    )


def _validate_unit(settings: dict[str, Any], location: str, adapter: AdapterType) -> None:
    unit = _text(settings.get("unit"), f"{location}.unit")
    expected_suffix = ".service" if adapter is AdapterType.SYSTEMD_SERVICE else ".timer"
    if not _UNIT_RE.fullmatch(unit) or not unit.endswith(expected_suffix):
        raise ConfigurationError(f"{location}.unit must be a non-empty {expected_suffix} unit name")
    if "restart_loop_threshold" in settings:
        _integer(settings["restart_loop_threshold"], f"{location}.restart_loop_threshold", minimum=1)
    if "verification_delay_seconds" in settings:
        _integer(settings["verification_delay_seconds"], f"{location}.verification_delay_seconds")


def _validate_process(settings: dict[str, Any], location: str) -> None:
    if "executable_path" in settings:
        path = _text(settings["executable_path"], f"{location}.executable_path")
        if not path.startswith("/"):
            raise ConfigurationError(f"{location}.executable_path must be absolute")
    if "pid_file" in settings:
        _text(settings["pid_file"], f"{location}.pid_file")
    if "expected_user" in settings:
        _text(settings["expected_user"], f"{location}.expected_user")
    minimum = _integer(settings.get("minimum_process_count", 1), f"{location}.minimum_process_count")
    maximum = _integer(settings.get("maximum_process_count", minimum), f"{location}.maximum_process_count")
    if maximum < minimum:
        raise ConfigurationError(f"{location}.maximum_process_count must be >= minimum_process_count")


def _validate_file(settings: dict[str, Any], location: str) -> None:
    _text(settings.get("path"), f"{location}.path")
    if "required" in settings:
        _boolean(settings["required"], f"{location}.required")
    if "freshness_threshold_seconds" in settings:
        _integer(settings["freshness_threshold_seconds"], f"{location}.freshness_threshold_seconds")
    if "structured_format" in settings:
        structured = _text(settings["structured_format"], f"{location}.structured_format")
        if structured not in {"json", "yaml", "toml"}:
            raise ConfigurationError(f"{location}.structured_format is invalid")
    for key in ("expected_permissions", "expected_owner", "expected_group", "checksum_policy"):
        if key in settings:
            _text(settings[key], f"{location}.{key}")


def _validate_http(settings: dict[str, Any], location: str) -> None:
    url = _text(settings.get("url"), f"{location}.url")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError(f"{location}.url must be an HTTP or HTTPS URL")
    if parsed.username or parsed.password or parsed.query:
        raise ConfigurationError(f"{location}.url must not contain credentials or query secrets")
    method = _text(settings.get("method", "GET"), f"{location}.method").upper()
    if method not in _HTTP_METHODS:
        raise ConfigurationError(f"{location}.method is invalid")
    statuses = _list(settings.get("expected_status_codes", [200]), f"{location}.expected_status_codes")
    if not statuses:
        raise ConfigurationError(f"{location}.expected_status_codes must not be empty")
    for index, status in enumerate(statuses):
        _integer(status, f"{location}.expected_status_codes[{index}]", minimum=100, maximum=599)
    _integer(settings.get("timeout_seconds", 5), f"{location}.timeout_seconds", minimum=1)
    _boolean(settings.get("tls_verify", True), f"{location}.tls_verify")
    if "credential_env" in settings:
        _env_reference(settings, "credential_env", location)


def _validate_tcp(settings: dict[str, Any], location: str) -> None:
    _text(settings.get("host"), f"{location}.host")
    _integer(settings.get("port"), f"{location}.port", minimum=1, maximum=65535)
    _integer(settings.get("timeout_seconds", 5), f"{location}.timeout_seconds", minimum=1)


def _validate_executable(settings: dict[str, Any], location: str) -> None:
    if "command" in settings or "shell" in settings:
        raise ConfigurationError(f"{location} must use executable_path and an argument list")
    executable = _text(settings.get("executable_path"), f"{location}.executable_path")
    if not executable.startswith("/"):
        raise ConfigurationError(f"{location}.executable_path must be an absolute allowlisted path")
    arguments = _list(settings.get("arguments", []), f"{location}.arguments")
    for index, argument in enumerate(arguments):
        _text(argument, f"{location}.arguments[{index}]")
    _integer(settings.get("timeout_seconds", 10), f"{location}.timeout_seconds", minimum=1)
    exit_codes = _list(settings.get("expected_exit_codes", [0]), f"{location}.expected_exit_codes")
    if not exit_codes:
        raise ConfigurationError(f"{location}.expected_exit_codes must not be empty")
    for index, code in enumerate(exit_codes):
        _integer(code, f"{location}.expected_exit_codes[{index}]", minimum=0, maximum=255)


def _validate_monitoring(adapter: AdapterType, settings: dict[str, Any], location: str) -> None:
    _reject_direct_secrets(settings, location)
    if adapter in {AdapterType.SYSTEMD_SERVICE, AdapterType.SYSTEMD_TIMER}:
        _validate_unit(settings, location, adapter)
    elif adapter in {AdapterType.PROCESS, AdapterType.PID_FILE}:
        _validate_process(settings, location)
    elif adapter in {
        AdapterType.FILE,
        AdapterType.JSON_FILE,
        AdapterType.YAML_FILE,
        AdapterType.TOML_FILE,
    }:
        _validate_file(settings, location)
    elif adapter is AdapterType.HTTP:
        _validate_http(settings, location)
    elif adapter is AdapterType.TCP:
        _validate_tcp(settings, location)
    elif adapter is AdapterType.EXECUTABLE_CHECK:
        _validate_executable(settings, location)
    else:
        if not settings:
            raise ConfigurationError(f"{location} must not be empty")


def _parse_target(data: Any, index: int) -> Target:
    item = _mapping(data, f"targets[{index}]")
    location = f"targets[{index}]"
    adapter = _enum(AdapterType, item.get("adapter_type"), f"{location}.adapter_type")
    monitoring = _mapping(item.get("monitoring"), f"{location}.monitoring")
    _validate_monitoring(adapter, monitoring, f"{location}.monitoring")
    tags = tuple(
        _text(tag, f"{location}.tags[{tag_index}]")
        for tag_index, tag in enumerate(_list(item.get("tags"), f"{location}.tags"))
    )
    return Target(
        id=_text(item.get("id"), f"{location}.id", identifier=True),
        display_name=_text(item.get("display_name"), f"{location}.display_name"),
        adapter_type=adapter,
        enabled=_boolean(item.get("enabled", True), f"{location}.enabled"),
        severity=_enum(Severity, item.get("severity"), f"{location}.severity"),
        monitoring=monitoring,
        repair_policy=_text(item.get("repair_policy"), f"{location}.repair_policy", identifier=True),
        notification_policy=(
            _text(
                item.get("notification_policy"),
                f"{location}.notification_policy",
                identifier=True,
            )
            if item.get("notification_policy") is not None
            else None
        ),
        tags=tags,
    )


def parse_config(data: Any) -> ShieldMendAiConfig:
    """Parse and validate a configuration mapping."""
    root = _mapping(data, "configuration")
    _reject_direct_secrets(root, "configuration")
    global_settings = _parse_global(_mapping(root.get("global"), "global"))
    policies = tuple(
        _parse_repair_policy(item, index)
        for index, item in enumerate(_list(root.get("repair_policies"), "repair_policies"))
    )
    channels = tuple(
        _parse_notification_channel(item, index)
        for index, item in enumerate(
            _list(root.get("notification_channels"), "notification_channels")
        )
    )
    notification_policies = tuple(
        _parse_notification_policy(item, index)
        for index, item in enumerate(
            _list(root.get("notification_policies"), "notification_policies")
        )
    )
    targets = tuple(
        _parse_target(item, index)
        for index, item in enumerate(_list(root.get("targets"), "targets"))
    )
    if not targets:
        raise ConfigurationError("targets must not be empty")
    for collection, name in (
        (policies, "repair_policies"),
        (channels, "notification_channels"),
        (notification_policies, "notification_policies"),
        (targets, "targets"),
    ):
        _unique_ids(collection, name)

    policy_ids = {item.id for item in policies}
    channel_ids = {item.id for item in channels}
    notification_policy_ids = {item.id for item in notification_policies}
    for target in targets:
        if target.repair_policy not in policy_ids:
            raise ConfigurationError(
                f"target '{target.id}' references unknown repair policy '{target.repair_policy}'"
            )
        if (
            target.notification_policy is not None
            and target.notification_policy not in notification_policy_ids
        ):
            raise ConfigurationError(
                f"target '{target.id}' references unknown notification policy"
            )
    for policy in notification_policies:
        unknown = sorted(set(policy.channels) - channel_ids)
        if unknown:
            raise ConfigurationError(
                f"notification policy '{policy.id}' references unknown channels"
            )
    return ShieldMendAiConfig(
        global_settings=global_settings,
        repair_policies=policies,
        notification_channels=channels,
        notification_policies=notification_policies,
        targets=targets,
    )


def load_config(path: str | Path) -> ShieldMendAiConfig:
    """Load YAML without resolving environment values or touching targets."""
    config_path = Path(path)
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except OSError:
        raise ConfigurationError("cannot read configuration file") from None
    except yaml.YAMLError:
        raise ConfigurationError("invalid YAML syntax") from None
    return parse_config(data)
