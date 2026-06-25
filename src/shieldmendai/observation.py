"""Simulation-only observation registry, adapters, and coordinator."""

from __future__ import annotations

import hashlib
import json
import stat
import tomllib
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .errors import AdapterError, ScenarioError, UnsafeObservationError
from .fixture_paths import resolve_fixture_path
from .interfaces import ObserverAdapter
from .models import (
    AdapterCapabilities,
    AdapterType,
    Confidence,
    ErrorClassification,
    Finding,
    FindingEvidence,
    ObservationContext,
    ObservationRequest,
    ObservationResult,
    ObservationStatus,
    ReliabilityCategory,
    Severity,
    ShieldMendAiConfig,
)
from .redaction import redact
from .scenarios import SimulationScenario

_SIMULATED_TYPES = (
    AdapterType.SYSTEMD_SERVICE,
    AdapterType.SYSTEMD_TIMER,
    AdapterType.PROCESS,
    AdapterType.PID_FILE,
    AdapterType.HTTP,
    AdapterType.TCP,
    AdapterType.EXECUTABLE_CHECK,
    AdapterType.FILE,
    AdapterType.JSON_FILE,
    AdapterType.YAML_FILE,
    AdapterType.TOML_FILE,
)


class AdapterRegistry:
    """Fixed registry that never imports plugins or customer code."""

    def __init__(self) -> None:
        self._adapters: dict[AdapterType, ObserverAdapter] = {}

    def register(self, adapter: ObserverAdapter) -> None:
        adapter_type = adapter.capabilities.adapter_type
        if adapter_type in self._adapters:
            raise AdapterError(f"adapter '{adapter_type.value}' is already registered")
        self._adapters[adapter_type] = adapter

    def get(self, adapter_type: AdapterType) -> ObserverAdapter:
        try:
            return self._adapters[adapter_type]
        except KeyError:
            raise AdapterError(f"adapter '{adapter_type.value}' is not registered") from None

    def capabilities(self) -> tuple[AdapterCapabilities, ...]:
        return tuple(
            self._adapters[key].capabilities
            for key in sorted(self._adapters, key=lambda item: item.value)
        )


def _finding(
    request: ObservationRequest,
    context: ObservationContext,
    *,
    status: ObservationStatus,
    category: ReliabilityCategory | None,
    summary: str,
    expected: Any,
    observed: Any,
    duration_ms: int,
    evidence: dict[str, Any] | None = None,
    error: ErrorClassification = ErrorClassification.NONE,
    retry: bool = False,
    manual_review: bool = False,
) -> Finding:
    severity = Severity.INFO if status is ObservationStatus.HEALTHY else request.target.severity
    return Finding(
        target_id=request.target.id,
        adapter_type=request.target.adapter_type,
        observed_at=context.observed_at,
        status=status,
        severity=severity,
        category=category,
        confidence=Confidence.DETERMINISTIC,
        summary=summary,
        sanitized_evidence=FindingEvidence(redact(evidence or {})),
        expected_state=redact(expected),
        observed_state=redact(observed),
        duration_ms=duration_ms,
        error_classification=error,
        retry_recommended=retry,
        manual_review_required=manual_review,
        simulation=True,
        adapter_version="1.0",
    )


class StateSimulationAdapter:
    """Maps validated scenario states to deterministic findings."""

    def __init__(self, adapter_type: AdapterType, supported_checks: tuple[str, ...]) -> None:
        self.capabilities = AdapterCapabilities(
            adapter_type=adapter_type,
            supported_checks=supported_checks,
            platform_requirements=("controlled scenario data",),
        )

    def observe(
        self, request: ObservationRequest, context: ObservationContext
    ) -> ObservationResult:
        state = request.scenario_state
        duration = int(request.scenario_data.get("duration_ms", 0))
        status, category, summary, error, retry, manual = self._map_state(state)
        finding = _finding(
            request,
            context,
            status=status,
            category=category,
            summary=summary,
            expected=request.target.monitoring.get("expected_state", "healthy"),
            observed=state,
            duration_ms=duration,
            evidence={"scenario_state": state, **request.scenario_data.get("data", {})},
            error=error,
            retry=retry,
            manual_review=manual,
        )
        return ObservationResult(
            request.target.id,
            request.target.adapter_type,
            status,
            (finding,),
            duration,
            True,
            self.capabilities.adapter_version,
        )

    def _map_state(
        self, state: str
    ) -> tuple[
        ObservationStatus,
        ReliabilityCategory | None,
        str,
        ErrorClassification,
        bool,
        bool,
    ]:
        adapter = self.capabilities.adapter_type
        healthy_states = {
            AdapterType.SYSTEMD_SERVICE: {"active"},
            AdapterType.SYSTEMD_TIMER: {"active"},
            AdapterType.PROCESS: {"present"},
            AdapterType.PID_FILE: {"present"},
            AdapterType.HTTP: {"healthy"},
            AdapterType.TCP: {"reachable"},
            AdapterType.EXECUTABLE_CHECK: {"expected_exit"},
        }
        if state in healthy_states.get(adapter, set()):
            return (
                ObservationStatus.HEALTHY, None, "Simulated observation is healthy",
                ErrorClassification.NONE, False, False
            )
        if adapter in {AdapterType.SYSTEMD_SERVICE, AdapterType.SYSTEMD_TIMER}:
            if state == "inactive":
                return (
                    ObservationStatus.UNHEALTHY, ReliabilityCategory.SERVICE_STOPPED,
                    "Simulated unit is inactive", ErrorClassification.SIMULATED_FAILURE,
                    True, False
                )
            if state == "failed":
                category = (
                    ReliabilityCategory.TIMER_FAILED
                    if adapter is AdapterType.SYSTEMD_TIMER
                    else ReliabilityCategory.SERVICE_FAILED
                )
                return (
                    ObservationStatus.UNHEALTHY, category, "Simulated unit failed",
                    ErrorClassification.SIMULATED_FAILURE, True, True
                )
            if state == "restart_loop":
                return (
                    ObservationStatus.UNHEALTHY, ReliabilityCategory.RESTART_LOOP,
                    "Simulated repeated restarts detected",
                    ErrorClassification.SIMULATED_FAILURE, False, True
                )
            if state == "activating":
                return (
                    ObservationStatus.DEGRADED, ReliabilityCategory.SERVICE_STOPPED,
                    "Simulated unit is still activating",
                    ErrorClassification.SIMULATED_FAILURE, True, False
                )
            return (
                ObservationStatus.UNKNOWN, ReliabilityCategory.SERVICE_STOPPED,
                "Simulated unit was not found", ErrorClassification.NOT_FOUND, False, True
            )
        if adapter in {AdapterType.PROCESS, AdapterType.PID_FILE}:
            if state == "missing":
                return (
                    ObservationStatus.UNHEALTHY, ReliabilityCategory.PROCESS_MISSING,
                    "Simulated process is missing", ErrorClassification.NOT_FOUND, True, False
                )
            return (
                ObservationStatus.UNHEALTHY, ReliabilityCategory.PROCESS_UNHEALTHY,
                "Simulated process state is unhealthy",
                ErrorClassification.MISMATCH, state != "wrong_user", True
            )
        if adapter is AdapterType.HTTP:
            error = ErrorClassification.TIMEOUT if state == "timeout" else ErrorClassification.SIMULATED_FAILURE
            return (
                ObservationStatus.UNHEALTHY, ReliabilityCategory.HTTP_UNHEALTHY,
                "Simulated HTTP check failed", error, True, state == "tls_failure"
            )
        if adapter is AdapterType.TCP:
            error = ErrorClassification.TIMEOUT if state == "timeout" else ErrorClassification.SIMULATED_FAILURE
            return (
                ObservationStatus.UNHEALTHY, ReliabilityCategory.TCP_UNREACHABLE,
                "Simulated TCP check failed", error, True, state in {"dns_failure", "invalid_endpoint"}
            )
        error = ErrorClassification.TIMEOUT if state == "timeout" else ErrorClassification.SIMULATED_FAILURE
        return (
            ObservationStatus.UNHEALTHY, ReliabilityCategory.APPLICATION_TEST_FAILURE,
            "Simulated executable check failed", error, state == "timeout", True
        )


class FixtureFileAdapter:
    """Read-only checks confined to a caller-provided fixture root."""

    def __init__(self, adapter_type: AdapterType) -> None:
        self.capabilities = AdapterCapabilities(
            adapter_type=adapter_type,
            supported_checks=(
                "exists", "freshness", "permissions", "sha256",
                "json_parse", "yaml_safe_parse", "toml_parse"
            ),
            platform_requirements=("explicit fixture root",),
        )

    def observe(
        self, request: ObservationRequest, context: ObservationContext
    ) -> ObservationResult:
        if not context.fixture_root:
            raise UnsafeObservationError("file observation requires an explicit fixture root")
        data = request.scenario_data.get("data", {})
        relative_path = data.get("fixture_path")
        if not isinstance(relative_path, str) or not relative_path:
            raise ScenarioError("fixture scenario requires data.fixture_path")
        path = resolve_fixture_path(context.fixture_root, relative_path)
        duration = int(request.scenario_data.get("duration_ms", 0))
        finding = self._inspect(path, request, context, duration, data)
        return ObservationResult(
            request.target.id,
            request.target.adapter_type,
            finding.status,
            (finding,),
            duration,
            True,
            self.capabilities.adapter_version,
        )

    def _inspect(
        self,
        path: Path,
        request: ObservationRequest,
        context: ObservationContext,
        duration: int,
        data: dict[str, Any],
    ) -> Finding:
        if not path.exists():
            return _finding(
                request, context, status=ObservationStatus.UNHEALTHY,
                category=ReliabilityCategory.FILE_MISSING, summary="Fixture file is missing",
                expected="present", observed="missing", duration_ms=duration,
                evidence={"fixture_path": path.name}, error=ErrorClassification.NOT_FOUND,
                retry=True
            )
        before = path.stat()
        raw = path.read_bytes()
        after = path.stat()
        if (before.st_mtime_ns, before.st_size) != (after.st_mtime_ns, after.st_size):
            raise UnsafeObservationError("fixture changed during observation")
        evidence: dict[str, Any] = {"fixture_path": path.name, "size_bytes": len(raw)}
        threshold = data.get(
            "freshness_threshold_seconds",
            request.target.monitoring.get("freshness_threshold_seconds"),
        )
        observed_at = datetime.fromisoformat(context.observed_at.replace("Z", "+00:00"))
        if threshold is not None:
            age = max(0, int(observed_at.timestamp() - before.st_mtime))
            evidence["age_seconds"] = age
            if age > int(threshold):
                return _finding(
                    request, context, status=ObservationStatus.UNHEALTHY,
                    category=ReliabilityCategory.FILE_STALE, summary="Fixture file is stale",
                    expected={"maximum_age_seconds": threshold}, observed={"age_seconds": age},
                    duration_ms=duration, evidence=evidence,
                    error=ErrorClassification.MISMATCH, retry=True
                )
        expected_mode = data.get(
            "expected_permissions", request.target.monitoring.get("expected_permissions")
        )
        actual_mode = format(stat.S_IMODE(before.st_mode), "04o")
        evidence["permission_mode"] = actual_mode
        if expected_mode is not None and actual_mode != str(expected_mode).removeprefix("0"):
            normalized_expected = format(int(str(expected_mode), 8), "04o")
            if actual_mode != normalized_expected:
                return _finding(
                    request, context, status=ObservationStatus.UNHEALTHY,
                    category=ReliabilityCategory.INCORRECT_PERMISSIONS,
                    summary="Fixture permission mode differs from expected",
                    expected=normalized_expected, observed=actual_mode, duration_ms=duration,
                    evidence=evidence, error=ErrorClassification.PERMISSION,
                    manual_review=True
                )
        checksum = hashlib.sha256(raw).hexdigest()
        expected_checksum = data.get("expected_sha256")
        if expected_checksum is not None and checksum != expected_checksum:
            evidence["sha256_matches"] = False
            return _finding(
                request, context, status=ObservationStatus.UNHEALTHY,
                category=ReliabilityCategory.UNEXPECTED_FILE_CHANGE,
                summary="Fixture checksum differs from expected", expected="configured sha256",
                observed="checksum mismatch", duration_ms=duration, evidence=evidence,
                error=ErrorClassification.MISMATCH, manual_review=True
            )
        parse_category = {
            AdapterType.JSON_FILE: ReliabilityCategory.INVALID_JSON,
            AdapterType.YAML_FILE: ReliabilityCategory.INVALID_YAML,
            AdapterType.TOML_FILE: ReliabilityCategory.INVALID_TOML,
        }.get(request.target.adapter_type)
        try:
            text = raw.decode("utf-8")
            if request.target.adapter_type is AdapterType.JSON_FILE:
                json.loads(text)
            elif request.target.adapter_type is AdapterType.YAML_FILE:
                yaml.safe_load(text)
            elif request.target.adapter_type is AdapterType.TOML_FILE:
                tomllib.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError, tomllib.TOMLDecodeError):
            return _finding(
                request, context, status=ObservationStatus.UNHEALTHY,
                category=parse_category, summary="Fixture structured data is invalid",
                expected="valid structured data", observed="parse error", duration_ms=duration,
                evidence=evidence, error=ErrorClassification.PARSE_ERROR,
                manual_review=True
            )
        evidence["content_valid"] = True
        if expected_checksum is not None:
            evidence["sha256_matches"] = True
        return _finding(
            request, context, status=ObservationStatus.HEALTHY, category=None,
            summary="Fixture observation is healthy", expected="valid fixture",
            observed="valid fixture", duration_ms=duration, evidence=evidence
        )


def build_simulation_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    for adapter_type in _SIMULATED_TYPES:
        if adapter_type in {
            AdapterType.FILE, AdapterType.JSON_FILE, AdapterType.YAML_FILE, AdapterType.TOML_FILE
        }:
            registry.register(FixtureFileAdapter(adapter_type))
        else:
            registry.register(
                StateSimulationAdapter(adapter_type, ("validated deterministic states",))
            )
    return registry


class ObservationCoordinator:
    """Validates target dispatch and runs only registered simulation adapters."""

    def __init__(self, registry: AdapterRegistry) -> None:
        self._registry = registry

    def run(
        self, config: ShieldMendAiConfig, scenario: SimulationScenario
    ) -> tuple[ObservationResult, ...]:
        configured = {target.id: target for target in config.targets}
        results: list[ObservationResult] = []
        context = ObservationContext(
            observed_at=scenario.observed_at,
            fixture_root=scenario.fixture_root,
            simulation=True,
        )
        for item in scenario.targets:
            target = configured.get(item.target_id)
            if target is None:
                raise ScenarioError(f"scenario references unknown target '{item.target_id}'")
            if target.adapter_type is not item.adapter_type:
                raise ScenarioError(f"scenario adapter type does not match target '{item.target_id}'")
            adapter = self._registry.get(item.adapter_type)
            if adapter.capabilities.production_available or not adapter.capabilities.supports_simulation:
                raise UnsafeObservationError("adapter is not permitted for Phase 3 simulation")
            request = ObservationRequest(
                target=target,
                scenario_state=item.state,
                scenario_data={"duration_ms": item.duration_ms, "data": item.data},
            )
            results.append(adapter.observe(request, context))
        return tuple(results)
