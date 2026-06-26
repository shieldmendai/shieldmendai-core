# ShieldMendAi Architecture

## Mission and Limits

ShieldMendAi is designed as a language-independent and server-independent
reliability and security recovery platform. Its intended lifecycle is:

```text
observe -> classify -> propose -> authorize -> act -> verify -> roll back/report
```

The product cannot guarantee protection of every server, detection of every
vulnerability, prevention of every attack, repair of every code failure, or
safe automatic repair in every situation.

## Phase 7 Boundary

Implemented now:

- typed models and YAML validation;
- normalized, redacted configuration display;
- deterministic planning-only output;
- observer protocol and typed requests, contexts, results, and findings;
- fixed adapter registry with explicit capabilities;
- deterministic simulation adapters for eleven configured adapter types;
- fixture-root-confined file and structured-file checks;
- scenario validation, simulation dispatch, and CLI output;
- automated tests.
- deny-by-default repair policy parsing and exact allowlists;
- typed requests, approvals, authorization decisions, plans, preconditions,
  verification plans, rollback plans, attempts, results, and audit events;
- deterministic simulation-only repair execution.
- explicit deterministic recovery lifecycle and transition validation;
- bounded retries, cooldown, backoff, failure windows, and circuit breakers;
- duplicate-attempt and idempotency protection;
- deterministic verification and rollback decisions;
- versioned, JSON-safe, non-secret recovery state.
- versioned sanitized incident records and explicit incident transitions;
- exact-scope correlation and canonical duplicate references;
- fixture-confined atomic incident JSON storage and integrity validation;
- deterministic retention preview and optional temporary-fixture removal;
- fixed simulated notifier registry for Telegram, email, SMS, webhook, and
  local alerts;
- deterministic routing, templates, rendering, duplicate suppression,
  cooldowns, attempt budgets, provider isolation, and notification audit data.
- installation and uninstall planning with temporary-root-confined simulation;
- checksummed installation manifests and installation audit events;
- least-privilege service-user, filesystem, permission, ownership, bootstrap,
  and systemd template plans;
- exact Linux target allowlists and a strict local-only pilot policy;
- read-only fixture observers, disabled production adapters, one-cycle pilot
  control, observation audits, and local incident linkage.

Modeled but not operational:

- production observation and repair, live verification and rollback,
  production incident persistence, production retention deletion, real
  notification delivery, real installers, systemd installation, deployment,
  plugins, and code repair.

Phase 7 performs no live systemd, process, socket, HTTP, DNS, SMTP,
subprocess, notification, vulnerability scan, package update, user creation,
permission or ownership change, repair, recovery, installation, or deployment
operation. File writes are limited to explicit temporary fixture roots.

## Platform and Language Independence

The initial core is Python, but applications remain in their native language.
Adapters operate at generic boundaries:

- `systemd_service`, `systemd_timer`, `process`, and `pid_file`;
- `tcp`, `http`, and `executable_check`;
- `file`, `json_file`, `yaml_file`, and `toml_file`;
- `database`, `container`, `kubernetes`, `windows_service`, and `plugin`.

Linux is the first planned operational platform. Windows services, Docker,
Kubernetes, cloud VMs, on-premise servers, websites, APIs, databases, and
background workers are represented as future extension points.

## Core Components

1. **Configuration loader** validates all settings without resolving secrets.
2. **Typed target models** describe observations at generic application and OS
   boundaries.
3. **Reliability and security categories** normalize future findings.
4. **Policy models** allow only observe, recommend, approval-required, or
   narrowly allowlisted automatic modes.
5. **Planner** describes configured targets and policy modes without execution.
6. **Redaction** removes credential values and sensitive references from
   display output and future incident/log boundaries.
7. **Incident model** records lifecycle status, sanitized evidence, proposed
   action, approval, verification, rollback, and notification outcomes.
8. **Notification protocols** isolate provider failure from core decisions.
9. **Plugin protocol** reserves a versioned, sanitized JSON boundary.
10. **Adapter registry** maps known adapter types to fixed simulation
    implementations and rejects duplicate, unknown, or unsafe dispatch.
11. **Observation coordinator** matches validated configuration targets to
    validated scenario targets and emits normalized findings.
12. **Fixture boundary** confines read-only file checks and rejects absolute
    target paths, traversal, and symlink escapes.
13. **Test harness** prohibits live subprocess, network, systemd, notification,
    and repair behavior.

## Normalized Observation

Every finding records target ID, adapter type, timestamp, status, severity,
category, confidence, summary, sanitized evidence, expected and observed
states, duration, error classification, retry recommendation, manual-review
requirement, simulation flag, and adapter version.

Statuses include healthy, degraded, unhealthy, unknown, skipped, unsupported,
and observation error. Phase 3 findings use deterministic confidence because
their source is controlled scenario or fixture input. They do not claim a real
production condition or confirmed security vulnerability.

## Finding and Incident Lifecycle

The status model distinguishes:

- suspected, detected, and confirmed;
- proposed repair and awaiting approval;
- approved or automatically permitted repair;
- repair attempted, successful, or unsuccessful;
- verification successful or failed;
- rollback completed;
- manual intervention required.

Incident evidence must be necessary, structured, and sanitized. It must not
contain secrets, full credentials, full private source files, or unnecessary
customer information.

## Safe Repair Policies

Supported policy modes are:

- `observe_only`
- `recommend`
- `require_approval`
- `auto_repair_low_risk`
- `auto_repair_allowlisted`

There is no unrestricted automatic mode. Future automatic repair requires
target and action allowlists, least privilege, pre-repair evidence, retry
limits, cooldowns, backup or rollback, post-repair verification, rollback after
failed verification, incident records, and customer notification.

## Code-Repair Safety Pipeline

The future model is:

1. Detect a reproducible failure.
2. Record sanitized evidence.
3. Identify an approved repository and branch.
4. Preserve the current commit and deployment version.
5. Create an isolated temporary workspace.
6. Generate a proposed patch.
7. Produce a human-readable diff.
8. Run configured tests.
9. Run linters.
10. Run type checks.
11. Run approved security checks.
12. Reject patches that fail required checks.
13. Require customer approval unless a narrowly defined low-risk allowlist
    permits automatic use.
14. Deploy through an approved mechanism.
15. Verify application health.
16. Roll back when verification fails.
17. Record and report the complete result.

ShieldMendAi must never silently rewrite arbitrary production code. Phase 2
does not generate, apply, commit, deploy, or roll back code.

## Notification Architecture

Future channels include Telegram, email, SMS, webhooks, and local structured
incident files. Credentials are environment references such as `token_env`,
`password_env`, or `url_env`; they are never resolved by Phase 2.

Channels can be selected by severity and have independent retry settings.
Provider failures must be isolated and must not crash or alter the future
recovery engine. No delivery adapter is implemented in Phase 2.

## Plugin Boundary

Future external plugins may communicate through versioned sanitized JSON over
standard input and output. Requests and responses declare schema versions,
request IDs, target IDs, capabilities, timeouts, sanitized parameters, results,
and errors.

Plugins require explicit allowlisting and capability declarations. They receive
no direct secrets, cannot use unrestricted shell execution, and cannot bypass
core policy. External plugin execution is not implemented in Phase 2.

## Self-Hosted Isolation

Customers install ShieldMendAi on their own systems. Configuration, credential
references, incidents, repositories, notification destinations, and
application metadata remain isolated per installation. The design introduces
no mandatory cloud service, shared customer database, shared credential,
automatic telemetry, or automatic upload.

## Exact Phase 8 Task

Deploy ShieldMendAi to its dedicated test server in a strictly read-only canary
configuration with verified server identity, a dedicated service user,
controlled checksummed installation, installed observer service and timer,
ShieldMendAi-owned test targets only, local incidents, and verified
rollback/uninstallation. Keep repairs, restarts, production notifications, and
customer deployment disabled.
