# Project Status

## Current Stage

Phase 2 — safe standalone framework and dry-run CLI.

## Implemented

- Installable `shieldmendai` Python package
- Typed configuration and validation
- Reliability and security category models
- Repair-policy and lifecycle models
- Incident and notification configuration models
- Recursive redaction utilities
- Planning-only CLI commands
- Language-independent example configuration
- Automated safety and validation tests

## Modeled Only

- systemd, process, PID, TCP, HTTP, file, database, container, Kubernetes,
  Windows service, and plugin adapters
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

Phase 3 will implement read-only observation interfaces and fake test adapters
for systemd, file, process, fixed executable, HTTP, and TCP targets. It will not
implement repair execution.
