"""Strict adapter protocols for simulation-only Phase 3 observations."""

from __future__ import annotations

from typing import Protocol

from .models import (
    AdapterCapabilities,
    Incident,
    NotificationChannelType,
    ObservationContext,
    ObservationRequest,
    ObservationResult,
)


class ObserverAdapter(Protocol):
    """A deterministic observer boundary with declared capabilities."""

    capabilities: AdapterCapabilities

    def observe(
        self, request: ObservationRequest, context: ObservationContext
    ) -> ObservationResult:
        """Return normalized findings without mutating or contacting a live target."""


class NotificationDeliveryResult(Protocol):
    delivered: bool
    sanitized_error: str | None


class NotificationAdapter(Protocol):
    """Future isolated notification provider boundary."""

    channel_type: NotificationChannelType

    def deliver(self, incident: Incident) -> NotificationDeliveryResult:
        """Deliver a redacted incident without affecting recovery state."""
