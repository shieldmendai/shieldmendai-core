# ShieldMendAi Extraction Plan

## Operating Rules

The private source at `/root/newbasebot` is read-only. Public work is written
only under `/root/ShieldMendAi`. Each phase ends before the next begins, and
every checkpoint requires a security review and a local Git commit. Pushing is
performed only when explicitly authorized and only to the official repository.

## Phase 1 — Read-only inventory and architecture

- Goal: identify reusable monitoring and recovery concepts without copying
  private implementation or operational data.
- Outputs: sanitized inventory, architecture, security boundaries, deployment
  plan, continuation record, manifest, and resume check.
- Tests: parse the manifest, run the resume check, verify required files, scan
  the public workspace, compare source hashes, and inspect the Git diff.
- Stop conditions: any unexplained public change, suspected secret exposure,
  source mutation, or uncertainty about whether material is private.
- Security review: exclude credentials, wallets, trading behavior, logs,
  reports, state, backups, databases, and customer data.
- Git checkpoint: `docs: establish resumable ShieldMendAi extraction plan`.

## Phase 2 — Standalone ShieldMendAi framework

- Goal: create the minimal `shieldmendai` package and typed configuration
  boundaries, with no live repair behavior.
- Outputs: package skeleton, configuration models, dry-run CLI, and test layout.
- Tests: imports, configuration validation, CLI help, and dry-run smoke tests.
- Stop conditions: any dependency on private paths, unit names, code, or data.
- Security review: confirm examples contain placeholders only and configuration
  never logs secret values.
- Git checkpoint: commit the framework and passing tests.

## Phase 3 — Generic monitoring and detection

- Goal: add read-only systemd, file, process, command, and HTTP health checks.
- Outputs: adapter interfaces, normalized health results, and fixtures.
- Tests: unit tests and isolated simulations for healthy, failed, stale,
  missing, invalid, timeout, and permission-denied targets.
- Stop conditions: a monitor mutates the host or accepts an unconfigured target.
- Security review: redact command output, URLs, headers, environment values,
  and file contents from incidents.
- Git checkpoint: commit generic monitors and simulation coverage.

## Phase 4 — Controlled repair actions

- Goal: execute only explicit, user-configured, allowlisted repairs.
- Outputs: policy engine, repair action models, dry-run plans, and executor.
- Tests: deny-by-default tests, allowlist tests, argument validation, timeout
  tests, and simulations that cannot affect host services.
- Stop conditions: arbitrary shell execution, implicit targets, or missing
  authorization boundaries.
- Security review: review privilege requirements, command construction, path
  confinement, and audit redaction.
- Git checkpoint: commit controlled actions and policy tests.

## Phase 5 — Recovery verification and loop protection

- Goal: verify recovery and prevent repeated or escalating repair loops.
- Outputs: post-repair probes, cooldowns, retry budgets, backoff, circuit
  breakers, and persistent non-secret controller state.
- Tests: failed verification, cooldown, retry exhaustion, restart-loop, and
  clock-boundary simulations.
- Stop conditions: unbounded retries, unverifiable success, or unsafe state
  persistence.
- Security review: ensure controller state contains no monitored file contents
  or credentials.
- Git checkpoint: commit verification and loop-protection behavior.

## Phase 6 — Incident records and optional alerts

- Goal: produce redacted local incidents and optional outbound notifications.
- Outputs: incident schema, recorder, retention controls, notifier interface,
  and optional Telegram adapter.
- Tests: schema, redaction, retention, notifier failure, throttling, and
  disabled-notifier tests.
- Stop conditions: secret-bearing incidents or mandatory network access.
- Security review: inspect every serialized field and notification template.
- Git checkpoint: commit incident and alert functionality.

## Phase 7 — Installer, configuration, and CLI

- Goal: make installation and operation explicit and reversible.
- Outputs: installer, public example configuration, CLI commands, and
  `shieldmendai-*.service` or `shieldmendai-*.timer` templates.
- Tests: clean install/uninstall in an isolated environment, permissions,
  configuration errors, and idempotency.
- Stop conditions: installer changes unrelated services or imports private data.
- Security review: least privilege, ownership, secret-file modes, and rollback.
- Git checkpoint: commit installation assets and documentation.

## Phase 8 — Automated tests and isolated simulations

- Goal: prove safety and behavior without touching production targets.
- Outputs: expanded unit, integration, fault-injection, and simulation suites.
- Tests: all supported failure and recovery paths, concurrency, malformed
  input, and regression cases.
- Stop conditions: tests require private infrastructure or live credentials.
- Security review: fixtures are synthetic and logs are redacted.
- Git checkpoint: commit the reproducible test suite and results.

## Phase 9 — Installation on the dedicated ShieldMendAi server

- Goal: install the public package in an isolated directory on the dedicated
  host.
- Outputs: reviewed deployment configuration and dry-run service installation.
- Tests: package verification, permissions, dry-run startup, and no-op probes.
- Stop conditions: private material appears on the host or isolation is absent.
- Security review: verify repository origin, commit, config permissions, and
  absence of private source artifacts.
- Git checkpoint: commit only sanitized deployment documentation or fixes.

## Phase 10 — Side-by-side validation

- Goal: compare observations from the new system with existing behavior without
  allowing the new system to repair production targets initially.
- Outputs: redacted comparison results, tuning decisions, and approval criteria.
- Tests: dry-run parity, false-positive rate, missed-failure review, and
  controlled synthetic incidents.
- Stop conditions: target interference, contradictory repair ownership, or
  sensitive comparison output.
- Security review: comparison data must be synthetic or redacted.
- Git checkpoint: commit approved generic tuning and test updates.

## Phase 11 — Retire old Guardian components

- Goal: remove or disable old components only after explicit user approval.
- Outputs: approved migration checklist, rollback plan, and final ownership map.
- Tests: new service health, alerting, rollback, and observation period.
- Stop conditions: no explicit approval, incomplete rollback, or failed
  validation.
- Security review: preserve required evidence securely without transferring
  private logs or state into the public project.
- Git checkpoint: commit public migration documentation; host actions remain a
  separately approved operation.
