"""Validated deterministic Phase 3 simulation scenarios."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .errors import ScenarioError, UnsafeObservationError
from .fixture_paths import validate_fixture_root
from .models import AdapterType

_STATES: dict[AdapterType, set[str]] = {
    AdapterType.SYSTEMD_SERVICE: {
        "active", "inactive", "failed", "activating", "restart_loop", "unit_not_found"
    },
    AdapterType.SYSTEMD_TIMER: {
        "active", "inactive", "failed", "activating", "restart_loop", "unit_not_found"
    },
    AdapterType.PROCESS: {"present", "missing", "wrong_count", "wrong_user", "unhealthy"},
    AdapterType.PID_FILE: {"present", "missing", "pid_mismatch", "unhealthy"},
    AdapterType.HTTP: {
        "healthy", "unexpected_status", "timeout", "tls_failure",
        "response_mismatch", "connection_failure"
    },
    AdapterType.TCP: {"reachable", "refused", "timeout", "dns_failure", "invalid_endpoint"},
    AdapterType.EXECUTABLE_CHECK: {
        "expected_exit", "unexpected_exit", "timeout", "missing", "malformed_arguments"
    },
    AdapterType.FILE: {"fixture"},
    AdapterType.JSON_FILE: {"fixture"},
    AdapterType.YAML_FILE: {"fixture"},
    AdapterType.TOML_FILE: {"fixture"},
}
_SENSITIVE_KEYS = {
    "token", "password", "secret", "api_key", "private_key", "authorization",
    "credential", "credentials", "command", "shell"
}


@dataclass(frozen=True)
class ScenarioTarget:
    target_id: str
    adapter_type: AdapterType
    state: str
    duration_ms: int
    data: dict[str, Any]


@dataclass(frozen=True)
class SimulationScenario:
    schema_version: str
    observed_at: str
    fixture_root: str | None
    targets: tuple[ScenarioTarget, ...]


def _check_values(value: Any, location: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if (
                normalized in _SENSITIVE_KEYS or normalized.endswith("_env")
            ) and item not in (None, ""):
                raise ScenarioError(f"{location}.{key} is prohibited in scenarios")
            _check_values(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_values(item, f"{location}[{index}]")
    elif isinstance(value, str):
        parsed = urlsplit(value)
        if parsed.username or parsed.password:
            raise ScenarioError(f"{location} contains credential-bearing data")
        if "/root/" + "newbasebot" in value:
            raise ScenarioError(f"{location} contains a prohibited private reference")


def parse_scenario(data: Any) -> SimulationScenario:
    if not isinstance(data, dict):
        raise ScenarioError("scenario must be a mapping")
    _check_values(data, "scenario")
    observed_at = data.get("observed_at")
    if not isinstance(observed_at, str):
        raise ScenarioError("scenario.observed_at must be an ISO-8601 timestamp")
    try:
        datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError:
        raise ScenarioError("scenario.observed_at must be an ISO-8601 timestamp") from None
    raw_targets = data.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ScenarioError("scenario.targets must be a non-empty list")
    targets: list[ScenarioTarget] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_targets):
        if not isinstance(raw, dict):
            raise ScenarioError(f"scenario.targets[{index}] must be a mapping")
        target_id = raw.get("target_id")
        if not isinstance(target_id, str) or not target_id:
            raise ScenarioError(f"scenario.targets[{index}].target_id is invalid")
        if target_id in seen:
            raise ScenarioError(f"scenario contains duplicate target id '{target_id}'")
        seen.add(target_id)
        try:
            adapter_type = AdapterType(raw.get("adapter_type"))
        except ValueError:
            raise ScenarioError(f"scenario target '{target_id}' has unknown adapter type") from None
        if adapter_type not in _STATES:
            raise ScenarioError(f"scenario target '{target_id}' uses an unsupported adapter")
        state = raw.get("state")
        if state not in _STATES[adapter_type]:
            raise ScenarioError(f"scenario target '{target_id}' has unsupported state")
        duration = raw.get("duration_ms", 0)
        if isinstance(duration, bool) or not isinstance(duration, int) or duration < 0:
            raise ScenarioError(f"scenario target '{target_id}' has invalid duration")
        target_data = raw.get("data", {})
        if not isinstance(target_data, dict):
            raise ScenarioError(f"scenario target '{target_id}' data must be a mapping")
        targets.append(ScenarioTarget(target_id, adapter_type, state, duration, target_data))
    fixture_root = data.get("fixture_root")
    if fixture_root is not None and (not isinstance(fixture_root, str) or not fixture_root):
        raise ScenarioError("scenario.fixture_root must be a path string")
    return SimulationScenario(
        schema_version=str(data.get("schema_version", "1.0")),
        observed_at=observed_at,
        fixture_root=fixture_root,
        targets=tuple(targets),
    )


def load_scenario(path: str | Path) -> SimulationScenario:
    scenario_path = Path(path)
    try:
        data = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))
    except OSError:
        raise ScenarioError("cannot read scenario file") from None
    except yaml.YAMLError:
        raise ScenarioError("invalid scenario YAML syntax") from None
    scenario = parse_scenario(data)
    fixture_root = scenario.fixture_root
    if fixture_root is not None and not Path(fixture_root).is_absolute():
        fixture_root = str((scenario_path.parent / fixture_root).absolute())
    if fixture_root is not None:
        try:
            fixture_root = str(validate_fixture_root(fixture_root))
        except (OSError, RuntimeError, UnsafeObservationError):
            raise ScenarioError("scenario fixture root is unsafe or unavailable") from None
    return SimulationScenario(
        scenario.schema_version, scenario.observed_at, fixture_root, scenario.targets
    )
