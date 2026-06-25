"""Future adapter protocols; Phase 2 provides no live implementations."""

from __future__ import annotations

from typing import Protocol

from .models import Incident, NotificationChannelType


class NotificationDeliveryResult(Protocol):
    delivered: bool
    sanitized_error: str | None


class NotificationAdapter(Protocol):
    """Future isolated notification provider boundary."""

    channel_type: NotificationChannelType

    def deliver(self, incident: Incident) -> NotificationDeliveryResult:
        """Deliver a redacted incident without affecting recovery state."""
