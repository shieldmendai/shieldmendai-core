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

- Status: complete on `codex/extraction-phase-2`.
- Goal: create the minimal `shieldmendai` package and typed configuration
  boundaries, with no live monitoring or repair behavior.
- Outputs: installable package, typed configuration and status models,
  redaction, dry-run CLI, safe example, and automated tests.
- Tests: imports, schema validation, negative validation cases, redaction, CLI
  smoke tests, planning-only guards, and repository safety checks.
- Stop conditions: any dependency on private paths, unit names, code, or data.
- Security review: confirm examples contain placeholders only and configuration
  never logs secret values.
- Git checkpoint: `feat: add safe ShieldMendAi framework and dry-run CLI`.

## Phase 3 — Generic monitoring and detection

- Status: complete on `codex/extraction-phase-3`.
- Goal: add safe observation interfaces and deterministic simulated systemd,
  file, process, executable, HTTP, and TCP health checks.
- Outputs: typed observation models, fixed adapter registry, capability
  declarations, normalized findings, validated scenarios, fixture-confined
  checks, CLI simulation commands, and tests.
- Tests: unit tests and isolated simulations for healthy, failed, stale,
  missing, invalid, timeout, and permission-denied targets.
- Stop conditions: a monitor mutates the host or accepts an unconfigured target.
- Security review: redact command output, URLs, headers, environment values,
  and file contents from incidents.
- Git checkpoint: `feat: add safe ShieldMendAi observation simulations`.

## Phase 4 — Controlled repair actions

- Status: complete on `codex/extraction-phase-4`.
- Goal: implement deny-by-default authorization and simulation-only execution
  for explicit, user-configured, allowlisted repairs.
- Outputs: policy engine, repair action models, dry-run plans, and safe
  simulation executors. Production mutation requires a later explicit phase.
- Tests: deny-by-default tests, allowlist tests, argument validation, timeout
  tests, and simulations that cannot affect host services.
- Stop conditions: arbitrary shell execution, implicit targets, or missing
  authorization boundaries.
- Security review: review privilege requirements, command construction, path
  confinement, and audit redaction.
- Git checkpoint: commit controlled actions and policy tests.

## Phase 5 — Recovery verification and loop protection

- Status: complete on `codex/extraction-phase-5`.
- Goal: add deterministic post-repair verification state transitions and
  prevent repeated or escalating repair loops without production mutation.
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

- Status: complete on `codex/extraction-phase-6`.
- Goal: produce redacted local incidents and optional outbound notifications.
- Outputs: typed incident schema and timelines, fixture-confined recorder,
  integrity validation, deterministic retention controls, fixed notifier
  interfaces, routing, templates, suppression, cooldowns, attempt budgets, and
  Telegram/email/SMS/webhook/local simulations.
- Tests: schema, redaction, retention, notifier failure, throttling, and
  disabled-notifier tests.
- Stop conditions: secret-bearing incidents or mandatory network access.
- Security review: inspect every serialized field and notification template.
- Git checkpoint: commit incident and alert functionality.

## Phase 7 — Dedicated-server sandbox and read-only Linux pilot

- Status: complete on `codex/extraction-phase-7`.

- Goal: create a controlled dedicated-server sandbox installation and a
  local-only, read-only Linux observation pilot.
- Outputs: installer/uninstaller simulation, least-privilege service-user
  planning, systemd unit templates, safe configuration bootstrap, read-only
  production-adapter interfaces, controlled test-server allowlist, and local
  incident persistence.
- Restrictions: no repairs, service restarts, notification delivery,
  private-source access, or customer deployment.
- Tests: isolated install/uninstall simulation, path and permission planning,
  allowlist enforcement, read-only observation, and idempotency.
- Security review: least privilege, local-only boundaries, no provider access,
  and no mutation of customer or private systems.

## Phase 8 — Dedicated test-server read-only canary

- Status: package prepared on `codex/extraction-phase-8`; manual deployment is
  still pending.
- Goal: deploy ShieldMendAi to its dedicated test server in a strictly
  read-only canary configuration.
- Outputs: verified server identity, dedicated service user, controlled
  checksummed installation, real local layout, installed observer service and
  timer, explicit ShieldMendAi-owned test-target allowlist, local incidents,
  and rollback/uninstall verification.
- Restrictions: no automatic repairs, service restarts, production
  notifications, customer deployment, unrelated targets, or private-source
  access.
- Stop conditions: server identity is uncertain, installation scope expands,
  a target is not ShieldMendAi-owned, read-only enforcement fails, or rollback
  cannot be verified.
- Result: created the canary configuration, preview/apply package model,
  hardened unit rendering, demo health target, incident workflow, rollback
  workflow, tests, and manual runbook. No live server contact or deployment was
  performed.

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

## Phase 11 — Retire legacy private components

- Goal: remove or disable old components only after explicit user approval.
- Outputs: approved migration checklist, rollback plan, and final ownership map.
- Tests: new service health, alerting, rollback, and observation period.
- Stop conditions: no explicit approval, incomplete rollback, or failed
  validation.
- Security review: preserve required evidence securely without transferring
  private logs or state into the public project.
- Git checkpoint: commit public migration documentation; host actions remain a
  separately approved operation.
