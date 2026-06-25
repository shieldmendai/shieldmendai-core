# Project Status

## Current Stage

Phase 3 — simulation-only observation and detection layer.

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

## Modeled Only

- Production systemd, process, PID, TCP, HTTP, executable, and file adapters
- Database, container, Kubernetes, Windows service, and plugin adapters
- Controlled repairs, verification, rollback, and incident persistence
- Telegram, email, SMS, webhook, and local notification delivery
- Isolated code-repair workflow

## Not Available

- Live monitoring or process inspection
- systemd or network access
- Repairs, restarts, file changes, or deployments
- Vulnerability or security scanning
- Notification delivery
- Production installer or dedicated-server deployment

## Next Task

Phase 4 will implement deny-by-default repair authorization and simulation-only
executors for explicit allowlisted actions. It will not implement production
mutation, arbitrary shell execution, deployment, or notification delivery.
