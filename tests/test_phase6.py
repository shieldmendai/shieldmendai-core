from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import smtplib
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shieldmendai.cli import run
from shieldmendai.errors import (
    IncidentTransitionError,
    IncidentValidationError,
    NotificationValidationError,
    UnsafeIncidentStoreError,
    UnsafeNotificationError,
)
from shieldmendai.incidents import (
    IncidentEventType,
    IncidentEvidenceReference,
    IncidentSource,
    IncidentStatus,
    LocalIncidentStore,
    RetentionDecision,
    correlate_incidents,
    create_incident_record,
    parse_incident_record,
    parse_retention_policy,
    preview_retention,
    simulate_retention,
    transition_incident,
)
from shieldmendai.models import AdapterType, Confidence, ReliabilityCategory, Severity
from shieldmendai.notifications import (
    NotificationChannelType,
    NotificationSimulator,
    NotifierRegistry,
    SimulatedDeliveryOutcome,
    SimulatedNotifier,
    build_simulated_notifier_registry,
    message_fingerprint,
    parse_notification_policy,
    parse_notification_scenario,
    parse_notification_template,
    render_notification,
    route_notification,
)


NOW = "2030-01-01T00:00:00Z"


def incident(
    incident_id: str = "incident-example",
    *,
    application_id: str = "application-example",
    severity: Severity = Severity.HIGH,
    timestamp: str = NOW,
):
    return create_incident_record(
        incident_id=incident_id,
        application_id=application_id,
        target_id="target-example",
        adapter_type=AdapterType.SYSTEMD_SERVICE,
        category=ReliabilityCategory.SERVICE_FAILED,
        severity=severity,
        confidence=Confidence.DETERMINISTIC,
        summary="Fictional service condition",
        sanitized_description="A deterministic fixture condition was recorded.",
        timestamp=timestamp,
        source=IncidentSource.SIMULATION,
        evidence_references=(
            IncidentEvidenceReference(
                "evidence-example",
                "normalized-finding",
                "Structured sanitized finding reference.",
            ),
        ),
        tags=("fictional",),
    )


def resolved_record(record=None, at: str = "2030-01-02T00:00:00Z"):
    item = record or incident()
    opened_at = (
        datetime.fromisoformat(at.replace("Z", "+00:00")) - timedelta(minutes=1)
    ).isoformat()
    item = transition_incident(
        item,
        IncidentStatus.OPEN,
        timestamp=opened_at,
        reason_code="opened",
        sanitized_message="Incident opened.",
    )
    return transition_incident(
        item,
        IncidentStatus.RESOLVED,
        timestamp=at,
        event_type=IncidentEventType.INCIDENT_RESOLVED,
        reason_code="resolved",
        sanitized_message="Incident resolved in simulation.",
    )


def policy_data(output_root: str, *, enabled: bool = True) -> dict:
    severities = ["info", "low", "medium", "high", "critical"]
    return {
        "schema_version": "1.0",
        "policy": {
            "routing_policy_id": "routing-example",
            "enabled": enabled,
            "default_channels": [],
            "severity_routes": {
                "low": ["local-example"],
                "high": ["telegram-example", "email-example"],
                "critical": [
                    "telegram-example",
                    "email-example",
                    "sms-example",
                    "webhook-example",
                    "local-example",
                ],
            },
            "event_routes": {
                "rollback_failed": ["webhook-example"],
                "manual_intervention_requested": ["sms-example"],
            },
            "status_routes": {},
            "escalation_routes": {
                "manual_intervention": ["telegram-example", "sms-example"],
                "rollback_failure": ["webhook-example"],
                "circuit_open": ["telegram-example"],
            },
            "suppressed_categories": [],
            "suppressed_targets": [],
            "minimum_severity": "info",
            "notification_cooldown_seconds": 60,
            "duplicate_window_seconds": 300,
            "maximum_attempts_per_channel": 3,
            "maximum_attempts_per_incident": 10,
            "minimum_interval_seconds": 0,
            "escalation_interval_seconds": 60,
            "severity_escalation_overrides_duplicate": True,
            "manual_intervention_overrides_duplicate": True,
            "simulation_only": True,
            "channels": [
                {
                    "channel_id": "telegram-example",
                    "notifier_type": "telegram",
                    "enabled": True,
                    "enabled_severities": severities,
                    "settings": {
                        "token_env": "SHIELDMENDAI_TELEGRAM_TOKEN_REF",
                        "chat_id_env": "SHIELDMENDAI_TELEGRAM_CHAT_REF",
                        "parse_mode": "plain",
                        "disable_preview": True,
                    },
                },
                {
                    "channel_id": "email-example",
                    "notifier_type": "email",
                    "enabled": True,
                    "enabled_severities": severities,
                    "settings": {
                        "provider_type": "smtp_future",
                        "smtp_host": "mail.example.invalid",
                        "port": 587,
                        "tls_required": True,
                        "username_env": "SHIELDMENDAI_EMAIL_USER_REF",
                        "password_env": "SHIELDMENDAI_EMAIL_PASSWORD_REF",
                        "from_address_reference": "address-ref-sender",
                        "recipient_references": ["address-ref-operations"],
                    },
                },
                {
                    "channel_id": "sms-example",
                    "notifier_type": "sms",
                    "enabled": True,
                    "enabled_severities": severities,
                    "settings": {
                        "provider_name": "fictional-provider",
                        "account_id_env": "SHIELDMENDAI_SMS_ACCOUNT_REF",
                        "token_env": "SHIELDMENDAI_SMS_TOKEN_REF",
                        "from_number_reference": "number-ref-sender",
                        "recipient_references": ["number-ref-operations"],
                    },
                },
                {
                    "channel_id": "webhook-example",
                    "notifier_type": "webhook",
                    "enabled": True,
                    "enabled_severities": severities,
                    "settings": {
                        "url_env": "SHIELDMENDAI_WEBHOOK_URL_REF",
                        "signing_secret_env": "SHIELDMENDAI_WEBHOOK_SIGNING_REF",
                        "timeout_seconds": 5,
                    },
                },
                {
                    "channel_id": "local-example",
                    "notifier_type": "local",
                    "enabled": True,
                    "enabled_severities": severities,
                    "settings": {"output_root": output_root, "format": "json"},
                },
            ],
        },
    }


def template_data(body: str = "Incident {incident_id}: {summary}") -> dict:
    return {
        "schema_version": "1.0",
        "template": {
            "template_id": "incident-opened-example",
            "event_type": "incident_created",
            "subject_template": "[{severity}] {summary}",
            "body_template": body,
            "maximum_length": 500,
        },
    }


def scenario_data(
    *,
    now: str = "2030-01-01T00:10:00Z",
    event_type: str = "incident_created",
    outcomes: dict[str, str] | None = None,
    previous: list[dict] | None = None,
) -> dict:
    return {
        "schema_version": "1.0",
        "scenario_id": "notification-example",
        "now": now,
        "event_type": event_type,
        "requested_production_delivery": False,
        "provider_outcomes": outcomes or {},
        "previous_notifications": previous or [],
        "remove_local_fixture_output": False,
        "simulation": True,
    }


def retention_data(**overrides) -> dict:
    policy = {
        "schema_version": "1.0",
        "retention_policy_id": "retention-example",
        "enabled": True,
        "maximum_age_days": 30,
        "maximum_record_count": 100,
        "maximum_total_bytes": 10000000,
        "retain_minimum_severity": "critical",
        "retain_unresolved": True,
        "retain_manual_intervention": True,
        "retain_latest_versions": True,
        "archive_before_delete": False,
        "dry_run": True,
        "review_required": False,
    }
    policy.update(overrides)
    return {"schema_version": "1.0", "policy": policy}


def cli(*args: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = run(list(args))
    return code, stdout.getvalue(), stderr.getvalue()


class IncidentModelTests(unittest.TestCase):
    def test_valid_record_round_trip_and_sanitization(self) -> None:
        record = incident()
        loaded = parse_incident_record(record.to_safe_dict())
        self.assertEqual(loaded, record)
        text = json.dumps(loaded.to_safe_dict()).lower()
        for prohibited in ("password", "private_key", "wallet", "authorization"):
            self.assertNotIn(prohibited, text)

    def test_schema_id_event_timestamp_checksum_and_version_validation(self) -> None:
        original = incident().to_safe_dict()
        cases = []
        unknown_schema = copy.deepcopy(original)
        unknown_schema["metadata"]["schema_version"] = "9.9"
        cases.append(unknown_schema)
        missing_id = copy.deepcopy(original)
        missing_id["incident_id"] = ""
        cases.append(missing_id)
        duplicate_event = copy.deepcopy(original)
        duplicate_event["events"].append(copy.deepcopy(duplicate_event["events"][0]))
        cases.append(duplicate_event)
        malformed_time = copy.deepcopy(original)
        malformed_time["events"][0]["timestamp"] = "invalid"
        cases.append(malformed_time)
        rollback = copy.deepcopy(original)
        rollback["metadata"]["record_version"] = 2
        rollback["metadata"]["previous_record_version"] = 2
        cases.append(rollback)
        checksum = copy.deepcopy(original)
        checksum["summary"] = "tampered"
        cases.append(checksum)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(IncidentValidationError):
                parse_incident_record(value)

    def test_lifecycle_transitions_events_and_terminal_states(self) -> None:
        opened = transition_incident(
            incident(),
            IncidentStatus.OPEN,
            timestamp="2030-01-01T00:01:00Z",
            reason_code="opened",
            sanitized_message="Opened.",
        )
        self.assertEqual(len(opened.events), 2)
        closed = transition_incident(
            transition_incident(
                opened,
                IncidentStatus.RESOLVED,
                timestamp="2030-01-01T00:02:00Z",
                reason_code="resolved",
                sanitized_message="Resolved.",
            ),
            IncidentStatus.CLOSED,
            timestamp="2030-01-01T00:03:00Z",
            event_type=IncidentEventType.INCIDENT_CLOSED,
            reason_code="closed",
            sanitized_message="Closed.",
        )
        with self.assertRaises(IncidentTransitionError):
            transition_incident(
                closed,
                IncidentStatus.OPEN,
                timestamp="2030-01-01T00:04:00Z",
                reason_code="reopen",
                sanitized_message="Reopen.",
            )
        with self.assertRaises(IncidentTransitionError):
            transition_incident(
                incident(),
                IncidentStatus.CLOSED,
                timestamp="2030-01-01T00:01:00Z",
                reason_code="invalid",
                sanitized_message="Invalid.",
            )

    def test_manual_intervention_does_not_auto_resolve(self) -> None:
        opened = transition_incident(
            incident(),
            IncidentStatus.OPEN,
            timestamp="2030-01-01T00:01:00Z",
            reason_code="opened",
            sanitized_message="Opened.",
        )
        manual = transition_incident(
            opened,
            IncidentStatus.MANUAL_INTERVENTION_REQUIRED,
            timestamp="2030-01-01T00:02:00Z",
            event_type=IncidentEventType.MANUAL_INTERVENTION_REQUESTED,
            reason_code="manual_required",
            sanitized_message="Manual review required.",
        )
        with self.assertRaises(IncidentTransitionError):
            transition_incident(
                manual,
                IncidentStatus.RESOLVED,
                timestamp="2030-01-01T00:03:00Z",
                reason_code="automatic",
                sanitized_message="Automatic resolution.",
            )

    def test_duplicate_requires_canonical_and_correlation_is_scope_safe(self) -> None:
        candidate = incident("incident-candidate")
        canonical = incident("incident-canonical")
        correlation = correlate_incidents(
            candidate, canonical, finding_fingerprint="finding-a", window_seconds=300
        )
        self.assertTrue(correlation.duplicate)
        duplicate = transition_incident(
            candidate,
            IncidentStatus.DUPLICATE,
            timestamp="2030-01-01T00:01:00Z",
            event_type=IncidentEventType.INCIDENT_MARKED_DUPLICATE,
            reason_code="duplicate",
            sanitized_message="Duplicate incident.",
            canonical_incident_id=canonical.incident_id,
        )
        self.assertEqual(
            duplicate.correlation.canonical_incident_id, canonical.incident_id
        )
        other_scope = incident("incident-other", application_id="application-other")
        self.assertFalse(
            correlate_incidents(
                other_scope,
                canonical,
                finding_fingerprint="finding-a",
                window_seconds=300,
            ).duplicate
        )


class IncidentStoreAndRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "incident-fixtures"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_store_confinement_and_unrelated_file(self) -> None:
        unrelated = Path(self.temporary.name) / "unrelated.txt"
        unrelated.write_text("unchanged", encoding="utf-8")
        store = LocalIncidentStore(self.root)
        path = store.write(incident())
        self.assertTrue(path.is_relative_to(self.root))
        self.assertEqual(store.read("incident-example.record.1").incident_id, "incident-example")
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "unchanged")

    def test_unsafe_absolute_traversal_private_and_symlink_roots(self) -> None:
        with self.assertRaises(UnsafeIncidentStoreError):
            LocalIncidentStore("/root")
        with self.assertRaises(UnsafeIncidentStoreError):
            LocalIncidentStore("/tmp/../root")
        with self.assertRaises(UnsafeIncidentStoreError):
            LocalIncidentStore("/root/" + "newbasebot")
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        link = Path(self.temporary.name) / "link"
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(UnsafeIncidentStoreError):
            LocalIncidentStore(link)

    def test_retention_policy_validation_defaults_and_protections(self) -> None:
        policy = parse_retention_policy(retention_data())
        self.assertTrue(policy.dry_run)
        for key in ("maximum_age_days", "maximum_record_count", "maximum_total_bytes"):
            invalid = retention_data(**{key: -1})
            with self.subTest(key=key), self.assertRaises(IncidentValidationError):
                parse_retention_policy(invalid)
        store = LocalIncidentStore(self.root)
        store.write(incident("incident-unresolved", timestamp="2020-01-01T00:00:00Z"))
        manual = transition_incident(
            transition_incident(
                incident("incident-manual", timestamp="2020-01-01T00:00:00Z"),
                IncidentStatus.OPEN,
                timestamp="2020-01-01T00:01:00Z",
                reason_code="opened",
                sanitized_message="Opened.",
            ),
            IncidentStatus.MANUAL_INTERVENTION_REQUIRED,
            timestamp="2020-01-01T00:02:00Z",
            reason_code="manual",
            sanitized_message="Manual intervention.",
        )
        store.write(manual)
        preview = preview_retention(store, policy, now="2030-01-01T00:00:00Z")
        decisions = {item.incident_id: item.decision for item in preview.candidates}
        self.assertEqual(
            decisions["incident-unresolved"], RetentionDecision.PROTECTED_UNRESOLVED
        )
        self.assertEqual(
            decisions["incident-manual"],
            RetentionDecision.PROTECTED_MANUAL_INTERVENTION,
        )

    def test_old_resolved_eligible_latest_version_and_preview_modify_nothing(self) -> None:
        store = LocalIncidentStore(self.root)
        old = resolved_record(
            incident("incident-old", timestamp="2020-01-01T00:00:00Z"),
            at="2020-01-01T00:02:00Z",
        )
        store.write(old)
        before = sorted(path.name for path in self.root.iterdir())
        policy = parse_retention_policy(retention_data())
        preview = preview_retention(store, policy, now="2030-01-01T00:00:00Z")
        self.assertEqual(
            preview.candidates[0].decision, RetentionDecision.ELIGIBLE_FOR_REMOVAL
        )
        self.assertEqual(before, sorted(path.name for path in self.root.iterdir()))
        newer = transition_incident(
            old,
            IncidentStatus.CLOSED,
            timestamp="2020-01-01T00:03:00Z",
            reason_code="closed",
            sanitized_message="Closed.",
        )
        store.write(newer)
        preview = preview_retention(store, policy, now="2030-01-01T00:00:00Z")
        latest = next(item for item in preview.candidates if item.record_version == 4)
        self.assertEqual(latest.decision, RetentionDecision.PROTECTED_LATEST_VERSION)

    def test_retention_fixture_removal_is_explicit_and_confined(self) -> None:
        unrelated = Path(self.temporary.name) / "unrelated.txt"
        unrelated.write_text("unchanged", encoding="utf-8")
        store = LocalIncidentStore(self.root)
        store.write(
            resolved_record(
                incident("incident-old", timestamp="2020-01-01T00:00:00Z"),
                at="2020-01-01T00:02:00Z",
            )
        )
        policy = parse_retention_policy(retention_data(dry_run=False))
        result = simulate_retention(
            store,
            policy,
            now="2030-01-01T00:00:00Z",
            remove_generated_fixtures=True,
        )
        self.assertEqual(result.removed_fixture_records, ("incident-old.record.3",))
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "unchanged")
        self.assertFalse(result.production_records_affected)


class NotificationValidationAndRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "alerts"
        self.root.mkdir()
        self.data = policy_data(str(self.root))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_notifier_capabilities_and_registry_rejection(self) -> None:
        registry = build_simulated_notifier_registry()
        capabilities = registry.capabilities()
        self.assertEqual(len(capabilities), 5)
        for item in capabilities:
            self.assertTrue(item.supports_simulation)
            self.assertFalse(item.production_delivery_available)
            self.assertFalse(item.network_used_in_phase6)
            self.assertFalse(item.secret_resolution_available)
        duplicate = NotifierRegistry()
        duplicate.register(SimulatedNotifier(NotificationChannelType.TELEGRAM))
        with self.assertRaises(NotificationValidationError):
            duplicate.register(SimulatedNotifier(NotificationChannelType.TELEGRAM))
        with self.assertRaises(NotificationValidationError):
            NotifierRegistry().get(NotificationChannelType.EMAIL)

    def test_direct_secrets_invalid_references_ports_timeouts_recipients(self) -> None:
        cases = []
        for index, key in ((0, "token"), (1, "password"), (2, "token"), (3, "url")):
            invalid = copy.deepcopy(self.data)
            invalid["policy"]["channels"][index]["settings"][key] = "direct-value"
            cases.append(invalid)
        invalid_env = copy.deepcopy(self.data)
        invalid_env["policy"]["channels"][0]["settings"]["token_env"] = "not-valid"
        cases.append(invalid_env)
        invalid_port = copy.deepcopy(self.data)
        invalid_port["policy"]["channels"][1]["settings"]["port"] = 70000
        cases.append(invalid_port)
        invalid_timeout = copy.deepcopy(self.data)
        invalid_timeout["policy"]["channels"][3]["settings"]["timeout_seconds"] = 0
        cases.append(invalid_timeout)
        empty = copy.deepcopy(self.data)
        empty["policy"]["channels"][1]["settings"]["recipient_references"] = []
        cases.append(empty)
        wildcard = copy.deepcopy(self.data)
        wildcard["policy"]["channels"][2]["settings"]["recipient_references"] = ["*"]
        cases.append(wildcard)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(NotificationValidationError):
                parse_notification_policy(value)

    def test_environment_references_are_accepted_never_resolved_and_production_denied(self) -> None:
        with mock.patch.dict(os.environ, {"SHIELDMENDAI_TELEGRAM_TOKEN_REF": "do-not-read"}):
            policy = parse_notification_policy(self.data)
        serialized = json.dumps(policy, default=str)
        self.assertNotIn("do-not-read", serialized)
        invalid = copy.deepcopy(self.data)
        invalid["policy"]["simulation_only"] = False
        with self.assertRaises(UnsafeNotificationError):
            parse_notification_policy(invalid)

    def test_unknown_routes_suppression_severity_and_empty_channels(self) -> None:
        unknown = copy.deepcopy(self.data)
        unknown["policy"]["severity_routes"]["high"] = ["missing"]
        with self.assertRaises(NotificationValidationError):
            parse_notification_policy(unknown)
        policy = parse_notification_policy(self.data)
        routed = {
            item.channel
            for item in route_notification(
                incident(), policy, IncidentEventType.INCIDENT_CREATED
            )
            if item.routed
        }
        self.assertEqual(
            routed, {NotificationChannelType.TELEGRAM, NotificationChannelType.EMAIL}
        )
        suppressed = copy.deepcopy(self.data)
        suppressed["policy"]["suppressed_targets"] = ["target-example"]
        self.assertFalse(
            any(
                item.routed
                for item in route_notification(
                    incident(),
                    parse_notification_policy(suppressed),
                    IncidentEventType.INCIDENT_CREATED,
                )
            )
        )
        disabled = parse_notification_policy(policy_data(str(self.root), enabled=False))
        self.assertFalse(
            any(
                item.routed
                for item in route_notification(
                    incident(), disabled, IncidentEventType.INCIDENT_CREATED
                )
            )
        )

    def test_manual_intervention_escalates(self) -> None:
        record = transition_incident(
            transition_incident(
                incident(),
                IncidentStatus.OPEN,
                timestamp="2030-01-01T00:01:00Z",
                reason_code="opened",
                sanitized_message="Opened.",
            ),
            IncidentStatus.MANUAL_INTERVENTION_REQUIRED,
            timestamp="2030-01-01T00:02:00Z",
            reason_code="manual",
            sanitized_message="Manual.",
        )
        channels = {
            item.channel
            for item in route_notification(
                record,
                parse_notification_policy(self.data),
                IncidentEventType.MANUAL_INTERVENTION_REQUESTED,
            )
            if item.routed
        }
        self.assertIn(NotificationChannelType.SMS, channels)
        self.assertIn(NotificationChannelType.TELEGRAM, channels)


class RenderingSuppressionAndDeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "alerts"
        self.root.mkdir()
        self.policy = parse_notification_policy(policy_data(str(self.root)))
        self.template = parse_notification_template(template_data())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_template_allowlist_rendering_redaction_and_truncation(self) -> None:
        invalid = template_data("Bad {unknown_variable}")
        with self.assertRaises(NotificationValidationError):
            parse_notification_template(invalid)
        rendered = render_notification(
            incident(),
            self.template,
            NotificationChannelType.TELEGRAM,
            rendered_at=NOW,
        )
        self.assertTrue(rendered.redacted)
        self.assertIn("SIMULATION ONLY", rendered.body)
        oversized = parse_notification_template(template_data("x" * 1000))
        truncated = render_notification(
            incident(),
            replace(oversized, maximum_length=100),
            NotificationChannelType.SMS,
            rendered_at=NOW,
        )
        self.assertTrue(truncated.truncated)
        self.assertIn("[TRUNCATED]", truncated.body)

    def test_duplicate_cooldown_and_attempt_budgets(self) -> None:
        record = incident()
        now = "2030-01-01T00:10:00Z"
        message = render_notification(
            record,
            self.template,
            NotificationChannelType.TELEGRAM,
            rendered_at=now,
        )
        fingerprint = message_fingerprint(
            record, IncidentEventType.INCIDENT_CREATED, NotificationChannelType.TELEGRAM, message
        )
        previous = [
            {
                "incident_id": record.incident_id,
                "event_type": "incident_created",
                "channel": "telegram",
                "severity": "high",
                "message_fingerprint": fingerprint,
                "simulated_at": "2030-01-01T00:09:30Z",
                "suppression_count": 0,
            }
        ]
        result = NotificationSimulator().simulate(
            record,
            self.policy,
            self.template,
            parse_notification_scenario(scenario_data(now=now, previous=previous)),
        )
        outcomes = {item.outcome for item in result.delivery_results}
        self.assertTrue(
            {
                SimulatedDeliveryOutcome.SUPPRESSED_DUPLICATE,
                SimulatedDeliveryOutcome.SUPPRESSED_COOLDOWN,
            }
            & outcomes
        )
        limited = replace(self.policy, maximum_attempts_per_channel=1)
        result = NotificationSimulator().simulate(
            record,
            limited,
            self.template,
            parse_notification_scenario(scenario_data(now=now, previous=previous)),
        )
        self.assertIn(
            SimulatedDeliveryOutcome.SUPPRESSED_RATE_LIMIT,
            {item.outcome for item in result.delivery_results},
        )

    def test_severity_escalation_override_requires_policy(self) -> None:
        record = incident(severity=Severity.HIGH)
        now = "2030-01-01T00:10:00Z"
        message = render_notification(
            record,
            self.template,
            NotificationChannelType.TELEGRAM,
            rendered_at=now,
        )
        fingerprint = message_fingerprint(
            record, IncidentEventType.INCIDENT_CREATED, NotificationChannelType.TELEGRAM, message
        )
        previous = [{
            "incident_id": record.incident_id,
            "event_type": "incident_created",
            "channel": "telegram",
            "severity": "medium",
            "message_fingerprint": fingerprint,
            "simulated_at": "2030-01-01T00:09:00Z",
            "suppression_count": 0,
        }]
        no_cooldown = replace(self.policy, notification_cooldown_seconds=0)
        allowed = NotificationSimulator().simulate(
            record,
            no_cooldown,
            self.template,
            parse_notification_scenario(scenario_data(now=now, previous=previous)),
        )
        self.assertIn(
            SimulatedDeliveryOutcome.SIMULATED_DELIVERY_SUCCESS,
            {item.outcome for item in allowed.delivery_results},
        )
        denied = NotificationSimulator().simulate(
            record,
            replace(no_cooldown, severity_escalation_overrides_duplicate=False),
            self.template,
            parse_notification_scenario(scenario_data(now=now, previous=previous)),
        )
        self.assertIn(
            SimulatedDeliveryOutcome.SUPPRESSED_DUPLICATE,
            {item.outcome for item in denied.delivery_results},
        )

    def test_provider_results_isolation_and_local_output(self) -> None:
        critical = incident(severity=Severity.CRITICAL)
        outcomes = {
            "telegram": "simulated_delivery_success",
            "email": "simulated_delivery_failure",
            "sms": "simulated_provider_unavailable",
            "webhook": "simulated_timeout",
            "local": "simulated_delivery_success",
        }
        result = NotificationSimulator().simulate(
            critical,
            self.policy,
            self.template,
            parse_notification_scenario(scenario_data(outcomes=outcomes)),
        )
        by_channel = {item.channel: item.outcome for item in result.delivery_results}
        self.assertEqual(
            by_channel[NotificationChannelType.TELEGRAM],
            SimulatedDeliveryOutcome.SIMULATED_DELIVERY_SUCCESS,
        )
        self.assertEqual(
            by_channel[NotificationChannelType.EMAIL],
            SimulatedDeliveryOutcome.SIMULATED_DELIVERY_FAILURE,
        )
        self.assertEqual(
            by_channel[NotificationChannelType.SMS],
            SimulatedDeliveryOutcome.SIMULATED_PROVIDER_UNAVAILABLE,
        )
        self.assertEqual(
            by_channel[NotificationChannelType.WEBHOOK],
            SimulatedDeliveryOutcome.SIMULATED_TIMEOUT,
        )
        self.assertTrue(list(self.root.glob("message.*.json")))
        for item in result.delivery_results:
            self.assertTrue(item.no_real_message_sent)
            self.assertTrue(item.no_external_provider_contacted)
            self.assertTrue(item.no_secret_resolved)

    def test_simulation_uses_no_live_boundaries(self) -> None:
        with (
            mock.patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
            mock.patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
            mock.patch.object(os, "system", side_effect=AssertionError("system")),
            mock.patch.object(time, "sleep", side_effect=AssertionError("sleep")),
            mock.patch.object(socket, "create_connection", side_effect=AssertionError("socket")),
            mock.patch.object(socket.socket, "connect", side_effect=AssertionError("socket")),
            mock.patch.object(smtplib, "SMTP", side_effect=AssertionError("smtp")),
            mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("http")),
            mock.patch.dict(os.environ, {}, clear=True),
        ):
            result = NotificationSimulator().simulate(
                incident(),
                self.policy,
                self.template,
                parse_notification_scenario(scenario_data()),
            )
        self.assertEqual(result.exit_code, 0)


class Phase6CliAndRepositoryTests(unittest.TestCase):
    def test_cli_labels_exit_codes_and_unsafe_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store_root = root / "store"
            alert_root = root / "alerts"
            store_root.mkdir()
            alert_root.mkdir()
            record = incident()
            incident_path = LocalIncidentStore(store_root).write(record)
            policy_path = root / "policy.yaml"
            template_path = root / "template.yaml"
            scenario_path = root / "scenario.yaml"
            retention_path = root / "retention.yaml"
            policy_path.write_text(yaml.safe_dump(policy_data(str(alert_root))), encoding="utf-8")
            template_path.write_text(yaml.safe_dump(template_data()), encoding="utf-8")
            scenario_path.write_text(yaml.safe_dump(scenario_data()), encoding="utf-8")
            retention_path.write_text(yaml.safe_dump(retention_data()), encoding="utf-8")
            self.assertIn("PRODUCTION NOTIFICATION DELIVERY IS UNAVAILABLE", cli("list-notifiers")[1])
            self.assertIn("NO NOTIFICATION SENT", cli("inspect-notification-policy", str(policy_path))[1])
            self.assertIn("NO NOTIFICATION SENT", cli("inspect-incident", str(incident_path))[1])
            self.assertIn("MESSAGE PREVIEW ONLY", cli("render-notification", str(incident_path), str(policy_path), str(template_path))[1])
            code, output, _ = cli("simulate-notification", str(incident_path), str(policy_path), str(scenario_path), "--template-path", str(template_path))
            self.assertEqual(code, 0)
            self.assertIn("NO EXTERNAL NOTIFICATION SENT", output)
            self.assertIn("RETENTION PREVIEW ONLY", cli("preview-retention", str(store_root), str(retention_path))[1])
        self.assertEqual(cli("inspect-incident-store", "/root")[0], 6)

    def test_cli_suppression_failure_integrity_and_production_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store_root = root / "store"
            alert_root = root / "alerts"
            store_root.mkdir()
            alert_root.mkdir()
            record = incident()
            incident_path = LocalIncidentStore(store_root).write(record)
            policy = policy_data(str(alert_root), enabled=False)
            policy_path = root / "policy.yaml"
            scenario_path = root / "scenario.yaml"
            policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
            scenario_path.write_text(yaml.safe_dump(scenario_data()), encoding="utf-8")
            self.assertEqual(cli("simulate-notification", str(incident_path), str(policy_path), str(scenario_path))[0], 2)
            policy_path.write_text(yaml.safe_dump(policy_data(str(alert_root))), encoding="utf-8")
            scenario_path.write_text(
                yaml.safe_dump(scenario_data(outcomes={"telegram": "simulated_delivery_failure"})),
                encoding="utf-8",
            )
            self.assertEqual(cli("simulate-notification", str(incident_path), str(policy_path), str(scenario_path))[0], 3)
            tampered = json.loads(incident_path.read_text(encoding="utf-8"))
            tampered["summary"] = "tampered"
            incident_path.write_text(json.dumps(tampered), encoding="utf-8")
            self.assertEqual(cli("inspect-incident", str(incident_path))[0], 5)
            unsafe = scenario_data()
            unsafe["requested_production_delivery"] = True
            scenario_path.write_text(yaml.safe_dump(unsafe), encoding="utf-8")
            self.assertEqual(cli("simulate-notification", str(incident_path), str(policy_path), str(scenario_path))[0], 5)

    def test_implementation_contains_no_prohibited_execution_or_domain_names(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "src" / "shieldmendai").glob("*.py")
        )
        for value in (
            "/root/" + "newbasebot",
            "new" + "base-",
            "shell=True",
            "eval(",
            "exec(",
            "pickle",
            "subprocess.run(",
            "subprocess.Popen(",
            "time.sleep(",
            "socket.connect(",
            "urlopen(",
            "smtplib.SMTP(",
            "systemctl ",
            "dbus.SystemBus(",
        ):
            with self.subTest(value=value):
                self.assertNotIn(value, source)
        examples = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "examples").rglob("*")
            if path.is_file()
        )
        self.assertNotIn("wallet", examples.lower())
        self.assertNotIn("trading", examples.lower())


if __name__ == "__main__":
    unittest.main()
