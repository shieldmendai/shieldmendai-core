"""Execution-free planning for configured targets."""

from __future__ import annotations

from .models import (
    DryRunPlan,
    NotificationChannelType,
    PlannedTarget,
    ShieldMendAiConfig,
)


def create_plan(config: ShieldMendAiConfig) -> DryRunPlan:
    """Create a deterministic plan without performing live operations."""
    repair_policies = {policy.id: policy for policy in config.repair_policies}
    notification_policies = {
        policy.id: policy for policy in config.notification_policies
    }
    channels = {channel.id: channel for channel in config.notification_channels}
    planned_targets: list[PlannedTarget] = []
    for target in config.targets:
        channel_types: tuple[NotificationChannelType, ...] = ()
        if target.notification_policy:
            channel_ids = notification_policies[target.notification_policy].channels
            channel_types = tuple(channels[item].channel_type for item in channel_ids)
        planned_targets.append(
            PlannedTarget(
                id=target.id,
                display_name=target.display_name,
                adapter_type=target.adapter_type,
                policy_mode=repair_policies[target.repair_policy].mode,
                notification_channel_types=channel_types,
            )
        )
    return DryRunPlan(
        installation_name=config.global_settings.installation_name,
        application_name=config.global_settings.application_name,
        dry_run=True,
        planning_only=True,
        targets=tuple(planned_targets),
    )
