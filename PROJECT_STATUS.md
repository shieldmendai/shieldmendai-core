# Project Status

## Current Stage

Phase 5 — deterministic recovery verification and loop protection.

## Implemented

- Installable `shieldmendai` Python package
- Typed configuration and validation
- Reliability and security category models
- Repair-policy and lifecycle models
- Incident and notification configuration models
- Recursive redaction utilities
- Planning-only CLI commands
- Typed observation models and normalized findings
- Fixed adapter registry and capability declarations
- Eleven deterministic simulation adapters
- Fixture-confined file, JSON, YAML, and TOML checks
- Scenario validation and simulation CLI commands
- Language-independent example configuration
- Automated safety and validation tests
- Typed repair requests, approvals, policies, authorization decisions, plans,
  preconditions, verification plans, rollback plans, results, and audit events
- Exact target/action allowlists and risk thresholds
- Deterministic simulation-only repair executor
- Phase 4 repair CLI commands and stable exit codes
- Explicit recovery lifecycle and validated transitions
- Bounded repair, verification, and rollback budgets
- Deterministic cooldown, backoff, failure windows, and circuit breakers
- Duplicate plan/request suppression and deterministic attempt IDs
- Verification evaluation, rollback decisions, and manual escalation
- Versioned JSON-safe recovery snapshots and Phase 5 CLI commands

## Modeled Only

- Production systemd, process, PID, TCP, HTTP, executable, and file adapters
- Database, container, Kubernetes, Windows service, and plugin adapters
- Production repairs, live verification, rollback execution, and production persistence
- Telegram, email, SMS, webhook, and local notification delivery
- Isolated code-repair workflow

## Not Available

- Live monitoring or process inspection
- systemd or network access
- Real repairs, restarts, file or permission changes, or deployments
- Vulnerability or security scanning
- Notification delivery
- Production installer or dedicated-server deployment

## Next Task

Phase 6 will add redacted local incident records, retention controls, notifier
interfaces, and optional alert modeling. Delivery remains disabled by default,
and production recovery remains unavailable.
