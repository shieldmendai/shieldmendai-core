# Project Status

## Current Stage

Phase 8 — dedicated-server read-only canary deployment package prepared.

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
- Typed installation, manifest, service-user, permission, ownership,
  bootstrap, unit-template, audit, and uninstall models
- Temporary-root-confined deterministic installation and uninstallation
- Checksummed installation manifest and conflict detection
- Exact Linux target allowlist and strict local pilot policy
- Read-only observer capabilities and disabled production adapters
- One-cycle fixture-backed pilot with local incident persistence
- Phase 7 installation and pilot CLI commands
- Dedicated canary configuration template
- Host identity validation for the manually verified canary server
- Preview-first and explicit-apply canary installation package model
- Checksummed canary installation manifest and sanitized installation audit
- Hardened canary systemd unit rendering, including the demo service
- ShieldMendAi-owned local demo health JSON target
- Read-only demo observation workflow with local incident creation and recovery
- Preview-first rollback that removes only manifest-owned unchanged files
- Phase 8 canary CLI commands and focused tests

## Modeled Only

- Production systemd, process, PID, TCP, HTTP, executable, and file adapters
- Database, container, Kubernetes, Windows service, and plugin adapters
- Production repairs, live verification, rollback execution, and production persistence
- Real Telegram, email, SMS, webhook, and local production delivery
- Production incident persistence and production retention deletion
- Isolated code-repair workflow
- Manual live application of the dedicated canary package

## Not Available

- Unrestricted live monitoring or process inspection
- systemd or network access
- Real repairs, restarts, file or permission changes, or deployments
- Vulnerability or security scanning
- Notification delivery
- Customer deployment
- Automatic deployment to the dedicated server

## Phase 8 Status

Deployment package prepared. Deployment is still pending manual operator
execution on the verified dedicated server. ShieldMendAi remains read-only:
no repairs, no restarts, no notifications, no network access, no customer
deployment, no trading-bot dependency, and no code rewriting.
