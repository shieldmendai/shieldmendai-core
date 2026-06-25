"""Deterministic notification routing, rendering, and provider simulation."""

from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from string import Formatter
from typing import Any, Protocol, TypeVar

import yaml

from .errors import NotificationValidationError, UnsafeNotificationError
from .incidents import (
    IncidentEventType,
    IncidentRecord,
    IncidentStatus,
    load_incident_record,
    validate_store_root,
)
from .models import Severity
from .redaction import REDACTED, redact, sanitize_message

SCHEMA_VERSION = "1.0"
MAX_ATTEMPTS = 100
MAX_INTERVAL = 31_536_000
_T = TypeVar("_T")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_ENV = re.compile(r"^[A-Z][A-Z0-9_]*$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
_SENSITIVE = re.compile(
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
ALLOWED_TEMPLATE_VARIABLES = frozenset(
    {
        "incident_id",
        "application_id",
        "target_id",
        "severity",
        "category",
        "status",
        "summary",
        "event_type",
        "recovery_state",
        "final_outcome",
        "manual_intervention_required",
        "timestamp",
    }
)


class NotificationChannelType(str, Enum):
    TELEGRAM = "telegram"
    EMAIL = "email"
    SMS = "sms"
    WEBHOOK = "webhook"
    LOCAL = "local"
    NONE = "none"


class SimulatedDeliveryOutcome(str, Enum):
    SIMULATED_DELIVERY_SUCCESS = "simulated_delivery_success"
    SIMULATED_DELIVERY_FAILURE = "simulated_delivery_failure"
    SIMULATED_TIMEOUT = "simulated_timeout"
    SIMULATED_PROVIDER_UNAVAILABLE = "simulated_provider_unavailable"
    SUPPRESSED_DUPLICATE = "suppressed_duplicate"
    SUPPRESSED_POLICY = "suppressed_policy"
    SUPPRESSED_COOLDOWN = "suppressed_cooldown"
    SUPPRESSED_RATE_LIMIT = "suppressed_rate_limit"
    UNSUPPORTED_CHANNEL = "unsupported_channel"
    INVALID_CONFIGURATION = "invalid_configuration"
    PRODUCTION_DELIVERY_DISABLED = "production_delivery_disabled"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


@dataclass(frozen=True)
class NotifierCapabilities:
    notifier_type: NotificationChannelType
    supports_simulation: bool
    production_delivery_available: bool
    requires_network: bool
    network_used_in_phase6: bool
    secret_resolution_available: bool


@dataclass(frozen=True)
class NotificationChannelConfiguration:
    channel_id: str
    notifier_type: NotificationChannelType
    enabled: bool
    enabled_severities: tuple[Severity, ...]
    settings: dict[str, Any]


@dataclass(frozen=True)
class NotificationRoutingPolicy:
    schema_version: str
    routing_policy_id: str
    enabled: bool
    default_channels: tuple[str, ...]
    severity_routes: dict[Severity, tuple[str, ...]]
    event_routes: dict[IncidentEventType, tuple[str, ...]]
    status_routes: dict[IncidentStatus, tuple[str, ...]]
    escalation_routes: dict[str, tuple[str, ...]]
    suppressed_categories: tuple[str, ...]
    suppressed_targets: tuple[str, ...]
    minimum_severity: Severity
    notification_cooldown_seconds: int
    duplicate_window_seconds: int
    maximum_attempts_per_channel: int
    maximum_attempts_per_incident: int
    minimum_interval_seconds: int
    escalation_interval_seconds: int
    severity_escalation_overrides_duplicate: bool
    manual_intervention_overrides_duplicate: bool
    simulation_only: bool
    channels: tuple[NotificationChannelConfiguration, ...]


@dataclass(frozen=True)
class NotificationTemplate:
    schema_version: str
    template_id: str
    event_type: IncidentEventType
    subject_template: str
    body_template: str
    maximum_length: int


@dataclass(frozen=True)
class RenderedMessage:
    message_id: str
    incident_id: str
    channel: NotificationChannelType
    subject: str
    body: str
    rendered_at: str
    template_id: str
    severity: Severity
    redacted: bool
    truncated: bool
    simulation: bool


@dataclass(frozen=True)
class NotificationRouteDecision:
    channel_id: str
    channel: NotificationChannelType
    routed: bool
    reason: str
    simulation: bool = True


@dataclass(frozen=True)
class NotificationSuppressionRecord:
    deduplication_key: str
    incident_id: str
    event_type: IncidentEventType
    channel: NotificationChannelType
    severity: Severity
    message_fingerprint: str
    duplicate_window_seconds: int
    last_simulated_at: str | None
    suppression_count: int
    outcome: SimulatedDeliveryOutcome
    next_eligible_attempt_at: str | None = None


@dataclass(frozen=True)
class NotificationAttempt:
    attempt_id: str
    incident_id: str
    channel_id: str
    channel: NotificationChannelType
    attempted_at: str
    attempt_number_for_channel: int
    attempt_number_for_incident: int
    simulation: bool = True


@dataclass(frozen=True)
class NotificationDeliveryResult:
    attempt: NotificationAttempt | None
    channel: NotificationChannelType
    outcome: SimulatedDeliveryOutcome
    retryable: bool
    sanitized_detail: str
    no_real_message_sent: bool = True
    no_external_provider_contacted: bool = True
    no_secret_resolved: bool = True
    simulation: bool = True


@dataclass(frozen=True)
class NotificationAuditEvent:
    event_id: str
    incident_id: str
    timestamp: str
    event_type: str
    channel: NotificationChannelType
    route_decision: str
    suppression_reason: str | None
    template_reference: str | None
    simulation_result: SimulatedDeliveryOutcome
    severity: Severity
    final_outcome: str
    simulation: bool = True


@dataclass(frozen=True)
class NotificationBatchResult:
    incident_id: str
    route_decisions: tuple[NotificationRouteDecision, ...]
    suppression_records: tuple[NotificationSuppressionRecord, ...]
    delivery_results: tuple[NotificationDeliveryResult, ...]
    audit_events: tuple[NotificationAuditEvent, ...]
    exit_code: int
    simulation: bool = True


@dataclass(frozen=True)
class NotificationScenario:
    schema_version: str
    scenario_id: str
    now: str
    event_type: IncidentEventType
    requested_production_delivery: bool
    provider_outcomes: dict[NotificationChannelType, SimulatedDeliveryOutcome]
    previous_notifications: tuple[dict[str, Any], ...]
    remove_local_fixture_output: bool = False
    simulation: bool = True


class Notifier(Protocol):
    capabilities: NotifierCapabilities

    def validate_configuration(self, config: NotificationChannelConfiguration) -> None: ...

    def simulate_delivery(
        self,
        config: NotificationChannelConfiguration,
        message: RenderedMessage,
        attempt: NotificationAttempt,
        outcome: SimulatedDeliveryOutcome,
    ) -> NotificationDeliveryResult: ...


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
        raise NotificationValidationError(f"{location} must be a mapping")
    return value


def _list(value: Any, location: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise NotificationValidationError(f"{location} must be a list")
    return list(value)


def _text(
    value: Any,
    location: str,
    *,
    identifier: bool = False,
    reference: bool = False,
    maximum: int = 2000,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise NotificationValidationError(f"{location} must be a non-empty string")
    result = sanitize_message(value.strip())
    if len(result) > maximum:
        raise NotificationValidationError(f"{location} is too long")
    if _FORBIDDEN_PRIVATE in result or _FORBIDDEN_PREFIX in result:
        raise NotificationValidationError(f"{location} contains a prohibited private reference")
    if _SENSITIVE.search(result):
        raise NotificationValidationError(f"{location} contains credential-like data")
    if identifier and not _ID.fullmatch(result):
        raise NotificationValidationError(f"{location} contains unsupported characters")
    if reference and not _REFERENCE.fullmatch(result):
        raise NotificationValidationError(f"{location} must be a sanitized reference")
    return result


def _boolean(value: Any, location: str) -> bool:
    if not isinstance(value, bool):
        raise NotificationValidationError(f"{location} must be true or false")
    return value


def _integer(value: Any, location: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise NotificationValidationError(
            f"{location} must be an integer between {minimum} and {maximum}"
        )
    return value


def _enum(enum_type: type[_T], value: Any, location: str) -> _T:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        raise NotificationValidationError(f"{location} is unknown") from None


def _timestamp(value: Any, location: str) -> str:
    text = _text(value, location, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise NotificationValidationError(f"{location} must be an ISO-8601 timestamp") from None
    if parsed.tzinfo is None:
        raise NotificationValidationError(f"{location} must include a timezone")
    return text


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _env(value: Any, location: str) -> str:
    text = _text(value, location)
    if not _ENV.fullmatch(text):
        raise NotificationValidationError(f"{location} must be an environment-variable name")
    return text


def _references(value: Any, location: str) -> tuple[str, ...]:
    values = tuple(
        _text(item, f"{location}[{index}]", reference=True)
        for index, item in enumerate(_list(value, location))
    )
    if not values:
        raise NotificationValidationError(f"{location} must not be empty")
    if any("*" in item for item in values):
        raise NotificationValidationError(f"{location} must use exact references")
    return values


def _validate_settings(
    notifier_type: NotificationChannelType, settings: dict[str, Any], location: str
) -> dict[str, Any]:
    direct_keys = {
        "token",
        "password",
        "secret",
        "api_key",
        "chat_id",
        "account_id",
        "url",
        "signing_secret",
    }
    if any(key in settings and settings[key] not in (None, "") for key in direct_keys):
        raise NotificationValidationError(
            f"{location} must use references rather than direct secret values"
        )
    clean: dict[str, Any] = {}
    if notifier_type is NotificationChannelType.TELEGRAM:
        clean = {
            "token_env": _env(settings.get("token_env"), f"{location}.token_env"),
            "chat_id_env": _env(settings.get("chat_id_env"), f"{location}.chat_id_env"),
            "parse_mode": _text(settings.get("parse_mode", "plain"), f"{location}.parse_mode", identifier=True),
            "disable_preview": _boolean(settings.get("disable_preview", True), f"{location}.disable_preview"),
        }
    elif notifier_type is NotificationChannelType.EMAIL:
        provider = _text(settings.get("provider_type"), f"{location}.provider_type", identifier=True)
        if provider not in {"smtp_future", "provider_future"}:
            raise NotificationValidationError(f"{location}.provider_type is unknown")
        clean = {
            "provider_type": provider,
            "smtp_host": _text(settings.get("smtp_host"), f"{location}.smtp_host"),
            "port": _integer(settings.get("port"), f"{location}.port", 1, 65535),
            "tls_required": _boolean(settings.get("tls_required", True), f"{location}.tls_required"),
            "username_env": _env(settings.get("username_env"), f"{location}.username_env"),
            "password_env": _env(settings.get("password_env"), f"{location}.password_env"),
            "from_address_reference": _text(
                settings.get("from_address_reference"),
                f"{location}.from_address_reference",
                reference=True,
            ),
            "recipient_references": _references(
                settings.get("recipient_references"), f"{location}.recipient_references"
            ),
        }
    elif notifier_type is NotificationChannelType.SMS:
        clean = {
            "provider_name": _text(settings.get("provider_name"), f"{location}.provider_name", identifier=True),
            "account_id_env": _env(settings.get("account_id_env"), f"{location}.account_id_env"),
            "token_env": _env(settings.get("token_env"), f"{location}.token_env"),
            "from_number_reference": _text(
                settings.get("from_number_reference"),
                f"{location}.from_number_reference",
                reference=True,
            ),
            "recipient_references": _references(
                settings.get("recipient_references"), f"{location}.recipient_references"
            ),
        }
    elif notifier_type is NotificationChannelType.WEBHOOK:
        clean = {
            "url_env": _env(settings.get("url_env"), f"{location}.url_env"),
            "signing_secret_env": (
                _env(settings.get("signing_secret_env"), f"{location}.signing_secret_env")
                if settings.get("signing_secret_env") is not None
                else None
            ),
            "timeout_seconds": _integer(
                settings.get("timeout_seconds"), f"{location}.timeout_seconds", 1, 300
            ),
        }
    elif notifier_type is NotificationChannelType.LOCAL:
        clean = {
            "output_root": _text(settings.get("output_root"), f"{location}.output_root"),
            "format": _text(settings.get("format", "json"), f"{location}.format", identifier=True),
        }
        if clean["format"] not in {"json", "text"}:
            raise NotificationValidationError(f"{location}.format is unknown")
    elif notifier_type is NotificationChannelType.NONE:
        if settings:
            raise NotificationValidationError("none notifier cannot have settings")
    return clean


def parse_notification_policy(data: Any) -> NotificationRoutingPolicy:
    root = _mapping(data, "notification policy")
    item = _mapping(root.get("policy", root), "policy")
    if item.get("schema_version", root.get("schema_version")) != SCHEMA_VERSION:
        raise NotificationValidationError("unsupported notification policy schema version")
    allowed = {
        "schema_version",
        "routing_policy_id",
        "enabled",
        "default_channels",
        "severity_routes",
        "event_routes",
        "status_routes",
        "escalation_routes",
        "suppressed_categories",
        "suppressed_targets",
        "minimum_severity",
        "notification_cooldown_seconds",
        "duplicate_window_seconds",
        "maximum_attempts_per_channel",
        "maximum_attempts_per_incident",
        "minimum_interval_seconds",
        "escalation_interval_seconds",
        "severity_escalation_overrides_duplicate",
        "manual_intervention_overrides_duplicate",
        "simulation_only",
        "channels",
    }
    if set(item) - allowed:
        raise NotificationValidationError("notification policy contains unknown fields")
    channels: list[NotificationChannelConfiguration] = []
    channel_ids: set[str] = set()
    for index, raw in enumerate(_list(item.get("channels"), "policy.channels")):
        channel = _mapping(raw, f"policy.channels[{index}]")
        channel_id = _text(channel.get("channel_id"), f"policy.channels[{index}].channel_id", identifier=True)
        if channel_id in channel_ids:
            raise NotificationValidationError("notification policy contains duplicate channel IDs")
        channel_ids.add(channel_id)
        notifier_type = _enum(
            NotificationChannelType,
            channel.get("notifier_type"),
            f"policy.channels[{index}].notifier_type",
        )
        severities = tuple(
            _enum(Severity, value, f"policy.channels[{index}].enabled_severities")
            for value in _list(
                channel.get("enabled_severities"),
                f"policy.channels[{index}].enabled_severities",
            )
        )
        if not severities:
            raise NotificationValidationError("enabled notification channel needs severities")
        settings = _validate_settings(
            notifier_type,
            _mapping(channel.get("settings", {}), f"policy.channels[{index}].settings"),
            f"policy.channels[{index}].settings",
        )
        channels.append(
            NotificationChannelConfiguration(
                channel_id,
                notifier_type,
                _boolean(channel.get("enabled", True), f"policy.channels[{index}].enabled"),
                severities,
                settings,
            )
        )

    def routes(
        key: str, enum_type: type[Enum] | None = None
    ) -> dict[Any, tuple[str, ...]]:
        result: dict[Any, tuple[str, ...]] = {}
        for route_key, raw_channels in _mapping(item.get(key, {}), f"policy.{key}").items():
            typed = _enum(enum_type, route_key, f"policy.{key}") if enum_type else _text(route_key, f"policy.{key}", identifier=True)
            values = tuple(
                _text(value, f"policy.{key}.{route_key}", identifier=True)
                for value in _list(raw_channels, f"policy.{key}.{route_key}")
            )
            if any(value not in channel_ids for value in values):
                raise NotificationValidationError(f"policy.{key} references unknown channel")
            result[typed] = values
        return result

    defaults = tuple(
        _text(value, "policy.default_channels", identifier=True)
        for value in _list(item.get("default_channels"), "policy.default_channels")
    )
    if any(value not in channel_ids for value in defaults):
        raise NotificationValidationError("default route references unknown channel")
    policy = NotificationRoutingPolicy(
        SCHEMA_VERSION,
        _text(item.get("routing_policy_id"), "policy.routing_policy_id", identifier=True),
        _boolean(item.get("enabled", True), "policy.enabled"),
        defaults,
        routes("severity_routes", Severity),
        routes("event_routes", IncidentEventType),
        routes("status_routes", IncidentStatus),
        routes("escalation_routes"),
        tuple(
            _text(value, "policy.suppressed_categories", identifier=True)
            for value in _list(item.get("suppressed_categories"), "policy.suppressed_categories")
        ),
        tuple(
            _text(value, "policy.suppressed_targets", identifier=True)
            for value in _list(item.get("suppressed_targets"), "policy.suppressed_targets")
        ),
        _enum(Severity, item.get("minimum_severity", "info"), "policy.minimum_severity"),
        _integer(
            item.get("notification_cooldown_seconds", 0),
            "policy.notification_cooldown_seconds",
            0,
            MAX_INTERVAL,
        ),
        _integer(
            item.get("duplicate_window_seconds", 0),
            "policy.duplicate_window_seconds",
            0,
            MAX_INTERVAL,
        ),
        _integer(
            item.get("maximum_attempts_per_channel", 1),
            "policy.maximum_attempts_per_channel",
            1,
            MAX_ATTEMPTS,
        ),
        _integer(
            item.get("maximum_attempts_per_incident", 1),
            "policy.maximum_attempts_per_incident",
            1,
            MAX_ATTEMPTS,
        ),
        _integer(
            item.get("minimum_interval_seconds", 0),
            "policy.minimum_interval_seconds",
            0,
            MAX_INTERVAL,
        ),
        _integer(
            item.get("escalation_interval_seconds", 0),
            "policy.escalation_interval_seconds",
            0,
            MAX_INTERVAL,
        ),
        _boolean(
            item.get("severity_escalation_overrides_duplicate", False),
            "policy.severity_escalation_overrides_duplicate",
        ),
        _boolean(
            item.get("manual_intervention_overrides_duplicate", True),
            "policy.manual_intervention_overrides_duplicate",
        ),
        _boolean(item.get("simulation_only", True), "policy.simulation_only"),
        tuple(channels),
    )
    if not policy.simulation_only:
        raise UnsafeNotificationError("production notification delivery is unavailable")
    return policy


def load_notification_policy(path: str | Path) -> NotificationRoutingPolicy:
    try:
        return parse_notification_policy(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
    except OSError:
        raise NotificationValidationError("cannot read notification policy") from None
    except yaml.YAMLError:
        raise NotificationValidationError("invalid notification policy syntax") from None


def parse_notification_template(data: Any) -> NotificationTemplate:
    root = _mapping(data, "notification template")
    item = _mapping(root.get("template", root), "template")
    if item.get("schema_version", root.get("schema_version")) != SCHEMA_VERSION:
        raise NotificationValidationError("unsupported notification template schema version")
    subject = _text(item.get("subject_template"), "template.subject_template", maximum=500)
    body = _text(item.get("body_template"), "template.body_template", maximum=10_000)
    for location, template in (("subject", subject), ("body", body)):
        try:
            fields = {
                field
                for _, field, format_spec, conversion in Formatter().parse(template)
                if field is not None
            }
        except ValueError:
            raise NotificationValidationError(f"template {location} syntax is invalid") from None
        if any("." in field or "[" in field or field not in ALLOWED_TEMPLATE_VARIABLES for field in fields):
            raise NotificationValidationError(f"template {location} uses an unknown variable")
        if any(format_spec or conversion for _, field, format_spec, conversion in Formatter().parse(template) if field):
            raise NotificationValidationError("template filters and conversions are unavailable")
    return NotificationTemplate(
        SCHEMA_VERSION,
        _text(item.get("template_id"), "template.template_id", identifier=True),
        _enum(IncidentEventType, item.get("event_type"), "template.event_type"),
        subject,
        body,
        _integer(item.get("maximum_length", 2000), "template.maximum_length", 64, 10_000),
    )


def load_notification_template(path: str | Path) -> NotificationTemplate:
    try:
        return parse_notification_template(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
    except OSError:
        raise NotificationValidationError("cannot read notification template") from None
    except yaml.YAMLError:
        raise NotificationValidationError("invalid notification template syntax") from None


def render_notification(
    incident: IncidentRecord,
    template: NotificationTemplate,
    channel: NotificationChannelType,
    *,
    rendered_at: str,
    event_type: IncidentEventType | None = None,
) -> RenderedMessage:
    when = _timestamp(rendered_at, "rendered_at")
    selected_event = event_type or template.event_type
    values = {
        "incident_id": incident.incident_id,
        "application_id": incident.application_id,
        "target_id": incident.target_id,
        "severity": incident.severity.value,
        "category": incident.category,
        "status": incident.status.value,
        "summary": incident.summary,
        "event_type": selected_event.value,
        "recovery_state": incident.current_recovery_state or "not_available",
        "final_outcome": incident.final_outcome.value,
        "manual_intervention_required": str(incident.manual_intervention_required).lower(),
        "timestamp": when,
    }
    subject = template.subject_template.format_map(values)
    body = template.body_template.format_map(values)
    subject = sanitize_message(subject)
    body = sanitize_message(body)
    if _SENSITIVE.search(subject + "\n" + body):
        subject = REDACTED
        body = "[REDACTED]"
    if channel in {NotificationChannelType.TELEGRAM, NotificationChannelType.WEBHOOK}:
        subject, body = html.escape(subject), html.escape(body)
    prefix = "SIMULATION ONLY — NO EXTERNAL NOTIFICATION SENT\n"
    body = prefix + body
    limit = min(
        template.maximum_length,
        {
            NotificationChannelType.TELEGRAM: 4096,
            NotificationChannelType.EMAIL: 10_000,
            NotificationChannelType.SMS: 480,
            NotificationChannelType.WEBHOOK: 8000,
            NotificationChannelType.LOCAL: 10_000,
            NotificationChannelType.NONE: 64,
        }[channel],
    )
    marker = "\n[TRUNCATED]"
    truncated = len(body) > limit
    if truncated:
        body = body[: max(0, limit - len(marker))] + marker
    if not subject or not body:
        raise NotificationValidationError("rendered notification content cannot be empty")
    fingerprint = hashlib.sha256(
        f"{incident.incident_id}|{channel.value}|{template.template_id}|{when}".encode()
    ).hexdigest()[:20]
    return RenderedMessage(
        f"message.{fingerprint}",
        incident.incident_id,
        channel,
        subject,
        body,
        when,
        template.template_id,
        incident.severity,
        True,
        truncated,
        True,
    )


class SimulatedNotifier:
    def __init__(self, notifier_type: NotificationChannelType) -> None:
        self.capabilities = NotifierCapabilities(
            notifier_type,
            True,
            False,
            notifier_type
            in {
                NotificationChannelType.TELEGRAM,
                NotificationChannelType.EMAIL,
                NotificationChannelType.SMS,
                NotificationChannelType.WEBHOOK,
            },
            False,
            False,
        )

    def validate_configuration(self, config: NotificationChannelConfiguration) -> None:
        if config.notifier_type is not self.capabilities.notifier_type:
            raise NotificationValidationError("notifier configuration type mismatch")
        _validate_settings(config.notifier_type, config.settings, "channel.settings")

    def simulate_delivery(
        self,
        config: NotificationChannelConfiguration,
        message: RenderedMessage,
        attempt: NotificationAttempt,
        outcome: SimulatedDeliveryOutcome,
    ) -> NotificationDeliveryResult:
        self.validate_configuration(config)
        if outcome not in {
            SimulatedDeliveryOutcome.SIMULATED_DELIVERY_SUCCESS,
            SimulatedDeliveryOutcome.SIMULATED_DELIVERY_FAILURE,
            SimulatedDeliveryOutcome.SIMULATED_TIMEOUT,
            SimulatedDeliveryOutcome.SIMULATED_PROVIDER_UNAVAILABLE,
        }:
            outcome = SimulatedDeliveryOutcome.MANUAL_REVIEW_REQUIRED
        retryable = outcome in {
            SimulatedDeliveryOutcome.SIMULATED_TIMEOUT,
            SimulatedDeliveryOutcome.SIMULATED_PROVIDER_UNAVAILABLE,
        }
        return NotificationDeliveryResult(
            attempt,
            config.notifier_type,
            outcome,
            retryable,
            "Deterministic provider simulation completed; no provider was contacted.",
        )


class LocalSimulatedNotifier(SimulatedNotifier):
    def simulate_delivery(
        self,
        config: NotificationChannelConfiguration,
        message: RenderedMessage,
        attempt: NotificationAttempt,
        outcome: SimulatedDeliveryOutcome,
    ) -> NotificationDeliveryResult:
        result = super().simulate_delivery(config, message, attempt, outcome)
        if outcome is SimulatedDeliveryOutcome.SIMULATED_DELIVERY_SUCCESS:
            root = validate_store_root(config.settings["output_root"])
            path = root / f"{message.message_id}.json"
            if path.is_symlink() or not path.parent.resolve().is_relative_to(root):
                raise UnsafeNotificationError("local alert output escaped fixture root")
            path.write_text(
                json.dumps(redact(_primitive(message)), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        return result


class NotifierRegistry:
    def __init__(self) -> None:
        self._notifiers: dict[NotificationChannelType, Notifier] = {}

    def register(self, notifier: Notifier) -> None:
        kind = notifier.capabilities.notifier_type
        if kind in self._notifiers:
            raise NotificationValidationError("duplicate notifier registration")
        self._notifiers[kind] = notifier

    def get(self, notifier_type: NotificationChannelType) -> Notifier:
        try:
            return self._notifiers[notifier_type]
        except KeyError:
            raise NotificationValidationError("unknown notifier type") from None

    def capabilities(self) -> tuple[NotifierCapabilities, ...]:
        return tuple(
            self._notifiers[key].capabilities
            for key in sorted(self._notifiers, key=lambda item: item.value)
        )


def build_simulated_notifier_registry() -> NotifierRegistry:
    registry = NotifierRegistry()
    for item in (
        NotificationChannelType.TELEGRAM,
        NotificationChannelType.EMAIL,
        NotificationChannelType.SMS,
        NotificationChannelType.WEBHOOK,
    ):
        registry.register(SimulatedNotifier(item))
    registry.register(LocalSimulatedNotifier(NotificationChannelType.LOCAL))
    return registry


def route_notification(
    incident: IncidentRecord,
    policy: NotificationRoutingPolicy,
    event_type: IncidentEventType,
) -> tuple[NotificationRouteDecision, ...]:
    channel_map = {item.channel_id: item for item in policy.channels}
    if (
        not policy.enabled
        or incident.target_id in policy.suppressed_targets
        or incident.category in policy.suppressed_categories
        or _SEVERITY_ORDER[incident.severity] < _SEVERITY_ORDER[policy.minimum_severity]
    ):
        return tuple(
            NotificationRouteDecision(
                item.channel_id, item.notifier_type, False, "suppressed_by_policy"
            )
            for item in policy.channels
        )
    selected = set(policy.default_channels)
    selected.update(policy.severity_routes.get(incident.severity, ()))
    selected.update(policy.event_routes.get(event_type, ()))
    selected.update(policy.status_routes.get(incident.status, ()))
    if incident.manual_intervention_required:
        selected.update(policy.escalation_routes.get("manual_intervention", ()))
    if event_type is IncidentEventType.ROLLBACK_FAILED:
        selected.update(policy.escalation_routes.get("rollback_failure", ()))
    if event_type is IncidentEventType.CIRCUIT_OPENED:
        selected.update(policy.escalation_routes.get("circuit_open", ()))
    return tuple(
        NotificationRouteDecision(
            item.channel_id,
            item.notifier_type,
            item.channel_id in selected
            and item.enabled
            and incident.severity in item.enabled_severities,
            (
                "selected_for_simulation"
                if item.channel_id in selected
                and item.enabled
                and incident.severity in item.enabled_severities
                else "channel_not_selected_or_disabled"
            ),
        )
        for item in policy.channels
        if item.notifier_type is not NotificationChannelType.NONE
    )


def message_fingerprint(
    incident: IncidentRecord,
    event_type: IncidentEventType,
    channel: NotificationChannelType,
    message: RenderedMessage,
) -> str:
    return hashlib.sha256(
        "|".join(
            (
                incident.incident_id,
                event_type.value,
                channel.value,
                message.subject,
                message.body,
            )
        ).encode()
    ).hexdigest()


def parse_notification_scenario(data: Any) -> NotificationScenario:
    root = _mapping(data, "notification scenario")
    if root.get("schema_version") != SCHEMA_VERSION:
        raise NotificationValidationError("unsupported notification scenario schema version")
    outcomes: dict[NotificationChannelType, SimulatedDeliveryOutcome] = {}
    for key, value in _mapping(root.get("provider_outcomes", {}), "provider_outcomes").items():
        outcomes[_enum(NotificationChannelType, key, "provider_outcomes")] = _enum(
            SimulatedDeliveryOutcome, value, f"provider_outcomes.{key}"
        )
    previous: list[dict[str, Any]] = []
    for index, raw in enumerate(_list(root.get("previous_notifications"), "previous_notifications")):
        item = _mapping(raw, f"previous_notifications[{index}]")
        previous.append(
            {
                "incident_id": _text(item.get("incident_id"), "previous.incident_id", identifier=True),
                "event_type": _enum(IncidentEventType, item.get("event_type"), "previous.event_type"),
                "channel": _enum(NotificationChannelType, item.get("channel"), "previous.channel"),
                "severity": _enum(Severity, item.get("severity"), "previous.severity"),
                "message_fingerprint": _text(item.get("message_fingerprint"), "previous.message_fingerprint"),
                "simulated_at": _timestamp(item.get("simulated_at"), "previous.simulated_at"),
                "suppression_count": _integer(item.get("suppression_count", 0), "previous.suppression_count", 0, MAX_ATTEMPTS),
            }
        )
    scenario = NotificationScenario(
        SCHEMA_VERSION,
        _text(root.get("scenario_id"), "scenario_id", identifier=True),
        _timestamp(root.get("now"), "now"),
        _enum(IncidentEventType, root.get("event_type"), "event_type"),
        _boolean(
            root.get("requested_production_delivery", False),
            "requested_production_delivery",
        ),
        outcomes,
        tuple(previous),
        _boolean(
            root.get("remove_local_fixture_output", False),
            "remove_local_fixture_output",
        ),
        _boolean(root.get("simulation", True), "simulation"),
    )
    if not scenario.simulation or scenario.requested_production_delivery:
        raise UnsafeNotificationError("production notification delivery is unavailable")
    return scenario


def load_notification_scenario(path: str | Path) -> NotificationScenario:
    try:
        return parse_notification_scenario(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
    except OSError:
        raise NotificationValidationError("cannot read notification scenario") from None
    except yaml.YAMLError:
        raise NotificationValidationError("invalid notification scenario syntax") from None


class NotificationSimulator:
    def __init__(self, registry: NotifierRegistry | None = None) -> None:
        self.registry = registry or build_simulated_notifier_registry()

    def simulate(
        self,
        incident: IncidentRecord,
        policy: NotificationRoutingPolicy,
        template: NotificationTemplate,
        scenario: NotificationScenario,
    ) -> NotificationBatchResult:
        if not policy.simulation_only or not scenario.simulation:
            raise UnsafeNotificationError("production notification delivery is unavailable")
        decisions = route_notification(incident, policy, scenario.event_type)
        suppressions: list[NotificationSuppressionRecord] = []
        results: list[NotificationDeliveryResult] = []
        audits: list[NotificationAuditEvent] = []
        incident_attempts = 0
        for decision in decisions:
            if not decision.routed:
                continue
            config = next(item for item in policy.channels if item.channel_id == decision.channel_id)
            message = render_notification(
                incident,
                template,
                decision.channel,
                rendered_at=scenario.now,
                event_type=scenario.event_type,
            )
            fingerprint = message_fingerprint(
                incident, scenario.event_type, decision.channel, message
            )
            prior = [
                item
                for item in scenario.previous_notifications
                if item["incident_id"] == incident.incident_id
                and item["event_type"] is scenario.event_type
                and item["channel"] is decision.channel
            ]
            channel_attempts = len(prior)
            suppression: SimulatedDeliveryOutcome | None = None
            next_time: str | None = None
            last = max(prior, key=lambda item: _time(item["simulated_at"])) if prior else None
            if channel_attempts >= policy.maximum_attempts_per_channel:
                suppression = SimulatedDeliveryOutcome.SUPPRESSED_RATE_LIMIT
            elif incident_attempts + len(scenario.previous_notifications) >= policy.maximum_attempts_per_incident:
                suppression = SimulatedDeliveryOutcome.SUPPRESSED_RATE_LIMIT
            elif last is not None:
                elapsed = (_time(scenario.now) - _time(last["simulated_at"])).total_seconds()
                required_interval = max(
                    policy.notification_cooldown_seconds,
                    policy.minimum_interval_seconds,
                )
                if elapsed < required_interval:
                    suppression = SimulatedDeliveryOutcome.SUPPRESSED_COOLDOWN
                    next_time = (
                        _time(last["simulated_at"])
                        + timedelta(seconds=required_interval)
                    ).isoformat()
                duplicate = (
                    last["message_fingerprint"] == fingerprint
                    and elapsed <= policy.duplicate_window_seconds
                )
                severity_override = (
                    policy.severity_escalation_overrides_duplicate
                    and _SEVERITY_ORDER[incident.severity]
                    > _SEVERITY_ORDER[last["severity"]]
                )
                manual_override = (
                    policy.manual_intervention_overrides_duplicate
                    and incident.manual_intervention_required
                )
                if duplicate and not severity_override and not manual_override:
                    suppression = SimulatedDeliveryOutcome.SUPPRESSED_DUPLICATE
            if suppression:
                record = NotificationSuppressionRecord(
                    hashlib.sha256(
                        f"{incident.incident_id}|{scenario.event_type.value}|{decision.channel.value}".encode()
                    ).hexdigest(),
                    incident.incident_id,
                    scenario.event_type,
                    decision.channel,
                    incident.severity,
                    fingerprint,
                    policy.duplicate_window_seconds,
                    last["simulated_at"] if last else None,
                    (last["suppression_count"] + 1) if last else 1,
                    suppression,
                    next_time,
                )
                suppressions.append(record)
                results.append(
                    NotificationDeliveryResult(
                        None,
                        decision.channel,
                        suppression,
                        False,
                        "Notification simulation was suppressed deterministically.",
                    )
                )
                audits.append(
                    NotificationAuditEvent(
                        f"{incident.incident_id}.{decision.channel.value}.suppression.audit",
                        incident.incident_id,
                        scenario.now,
                        IncidentEventType.NOTIFICATION_SUPPRESSED.value,
                        decision.channel,
                        decision.reason,
                        suppression.value,
                        template.template_id,
                        suppression,
                        incident.severity,
                        incident.final_outcome.value,
                    )
                )
                continue
            incident_attempts += 1
            attempt = NotificationAttempt(
                f"{incident.incident_id}.{decision.channel.value}.{channel_attempts + 1}",
                incident.incident_id,
                decision.channel_id,
                decision.channel,
                scenario.now,
                channel_attempts + 1,
                incident_attempts,
            )
            outcome = scenario.provider_outcomes.get(
                decision.channel,
                SimulatedDeliveryOutcome.SIMULATED_DELIVERY_SUCCESS,
            )
            try:
                result = self.registry.get(decision.channel).simulate_delivery(
                    config, message, attempt, outcome
                )
            except (NotificationValidationError, UnsafeNotificationError):
                result = NotificationDeliveryResult(
                    attempt,
                    decision.channel,
                    SimulatedDeliveryOutcome.INVALID_CONFIGURATION,
                    False,
                    "Provider simulation configuration was rejected.",
                )
            results.append(result)
            audits.append(
                NotificationAuditEvent(
                    f"{attempt.attempt_id}.audit",
                    incident.incident_id,
                    scenario.now,
                    IncidentEventType.NOTIFICATION_SIMULATED.value,
                    decision.channel,
                    decision.reason,
                    None,
                    template.template_id,
                    result.outcome,
                    incident.severity,
                    incident.final_outcome.value,
                )
            )
        if any(
            item.outcome
            in {
                SimulatedDeliveryOutcome.SIMULATED_DELIVERY_FAILURE,
                SimulatedDeliveryOutcome.SIMULATED_TIMEOUT,
                SimulatedDeliveryOutcome.SIMULATED_PROVIDER_UNAVAILABLE,
                SimulatedDeliveryOutcome.INVALID_CONFIGURATION,
            }
            for item in results
        ):
            exit_code = 3
        elif suppressions or not any(item.routed for item in decisions):
            exit_code = 2
        else:
            exit_code = 0
        return NotificationBatchResult(
            incident.incident_id,
            decisions,
            tuple(suppressions),
            tuple(results),
            tuple(audits),
            exit_code,
        )


def safe_notification_policy_dict(policy: NotificationRoutingPolicy) -> dict[str, Any]:
    return redact(_primitive(policy))


def load_notification_inputs(
    incident_path: str | Path,
    policy_path: str | Path,
    template_path: str | Path,
) -> tuple[IncidentRecord, NotificationRoutingPolicy, NotificationTemplate]:
    return (
        load_incident_record(incident_path),
        load_notification_policy(policy_path),
        load_notification_template(template_path),
    )
