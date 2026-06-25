# Project Status

## Current Stage

Phase 6 — safe incident records, retention controls, and deterministic
notification simulation.

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
- Versioned sanitized incident records, explicit lifecycle transitions, typed
  timelines, exact-scope correlation, and duplicate handling
- Temporary-root-confined incident storage with checksum and version validation
- Deterministic retention preview and fixture-only removal simulation
- Fixed Telegram, email, SMS, webhook, and local simulated notifier interfaces
- Severity/event/status/escalation routing and provider failure isolation
- Allowlisted templates, redaction, escaping, bounded rendering, and truncation
- Duplicate suppression, cooldown, per-channel/per-incident attempt budgets,
  simulated delivery results, and audit events
- Phase 6 inspection, preview, rendering, and simulation CLI commands

## Modeled Only

- Production systemd, process, PID, TCP, HTTP, executable, and file adapters
- Database, container, Kubernetes, Windows service, and plugin adapters
- Production repairs, live verification, rollback execution, and production persistence
- Real Telegram, email, SMS, webhook, and local production delivery
- Production incident persistence and production retention deletion
- Isolated code-repair workflow

## Not Available

- Live monitoring or process inspection
- systemd or network access
- Real repairs, restarts, file or permission changes, or deployments
- Vulnerability or security scanning
- Notification delivery
- Production installer or dedicated-server deployment

## Next Task

Create a controlled dedicated-server sandbox installation and a local-only,
read-only Linux observation pilot for ShieldMendAi. Do not add repairs, service
restarts, notification delivery, customer deployment, or private-source access.
