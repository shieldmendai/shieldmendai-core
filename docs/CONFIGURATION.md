# ShieldMendAi Configuration

Configuration is YAML and dry-run-only. The canonical planning example is
`examples/shieldmendai.example.yaml`.

## Global Settings

Required fields include schema and installation identity, environment,
`dry_run: true`, polling interval, incident directory, log level, default
policy mode, retry limit, cooldown, and verification delay.

Phase 2 rejects `dry_run: false`.

## Targets

Every target has a unique ID, display name, adapter type, enabled flag,
severity, adapter-specific monitoring settings, repair policy reference,
optional notification policy reference, and tags.

Supported modeled adapter types:

```text
systemd_service  systemd_timer  process  pid_file  tcp  http
file  json_file  yaml_file  toml_file  executable_check
database  container  kubernetes  windows_service  plugin
```

Phase 3 can dispatch only registered simulation adapters. Production access is
unavailable for every adapter.

Executable checks accept only an absolute `executable_path`, a structured
argument list, timeout, and expected exit codes. Shell command strings are
rejected.

HTTP configuration rejects authenticated URLs and query-bearing URLs. Secret
material must be represented by an environment-variable reference.

## Reliability Categories

The typed model includes service stopped/failed, timer failure, missing or
unhealthy processes, restart loops, unhealthy HTTP, unreachable TCP, missing or
stale files, invalid JSON/YAML/TOML/configuration, incorrect permissions or
ownership, disk/memory/CPU pressure, dependency and deployment failures,
certificate expiry, database unavailability, application test failures,
unexpected file changes, and unknown failures.

Phase 3 maps deterministic scenario and fixture observations to these
categories. It performs no production detection.

## Security Categories

The typed model includes operating-system and application-dependency
vulnerabilities, insecure configuration, exposed services or ports, dangerous
permissions, secret-exposure indicators, outdated software, weak TLS,
certificate problems, unauthorized file changes, suspicious processes or
service behavior, baseline violations, and unknown security findings.

These remain classification values only; Phase 3 performs no security scan and
does not confirm vulnerabilities from simulations.

## Policies

Repair policies use one of:

```text
observe_only
recommend
require_approval
auto_repair_low_risk
auto_repair_allowlisted
```

Phase 4 repair policy files add exact target IDs, adapter types, actions,
target/action pairs, maximum risk, optional finding categories and severity
ranges, retry/cooldown settings, and verification/rollback requirements.
Empty allowlists deny execution. Wildcards and duplicate or contradictory
entries are rejected. There is no fix-everything mode.

Incident lifecycle values distinguish suspected, detected, confirmed, proposed
repair, awaiting approval, approved repair, automatically permitted repair,
repair attempted/successful/unsuccessful, verification successful/failed,
rollback completed, and manual intervention required.

## Notifications

Telegram, email, SMS, and webhook settings use environment references. Local
incident-file settings use an isolated directory. Phase 2 never reads an
environment secret or sends a notification.

## Validation

```bash
shieldmendai validate-config examples/shieldmendai.example.yaml
```

Configuration validation rejects duplicate or empty IDs, unsupported adapters, invalid
timing and retry values, invalid severities and policies, invalid ports and
HTTP methods, direct credential values, unrestricted executable strings,
private-source references, and legacy private unit names.

## Redacted Display

```bash
shieldmendai show-config examples/shieldmendai.example.yaml
```

Credential-reference fields are redacted. Environment values are never
resolved.

## Planning

```bash
shieldmendai plan examples/shieldmendai.example.yaml
```

The plan lists target types, policy modes, and notification channel types. It
performs no live observation or action.

## Phase 3 Scenarios

See [Phase 3 simulation](SIMULATION.md) for the scenario schema, fixture-root
rules, supported deterministic states, normalized findings, and exit codes.

## Phase 4 Repairs

See [Phase 4 repair authorization and simulation](REPAIRS.md) for repair
request, approval, policy, verification, rollback, scenario, CLI, audit, and
exit-code details. All repair execution remains deterministic simulation.

## Phase 5 Recovery

See [Phase 5 deterministic recovery](RECOVERY.md) for versioned recovery
policies and state, lifecycle transitions, retry budgets, cooldown, fixed,
linear and exponential backoff, circuit breakers, verification evaluation,
rollback decisions, idempotency, loop protection, CLI commands, and exit
codes. Cooldown bypass and jitter are disabled. All timestamps and outcomes
are supplied deterministic data.

## Phase 6 Incidents, Retention, and Notifications

See [Phase 6 incidents and notification simulation](INCIDENTS_AND_NOTIFICATIONS.md).
Incident JSON is versioned and checksummed after sanitization. Stores must be
explicit temporary roots. Retention defaults to preview-only.

Notification policies define exact channel IDs, severity/event/status routes,
suppression, cooldowns, and finite attempt budgets. Provider settings contain
only environment-variable names and sanitized destination references.
Environment variables are never resolved. `simulation_only: true` is required,
and all Telegram, email, SMS, webhook, and local behavior is deterministic
simulation.

## Phase 7 Installation and Linux Pilot

Installation plans use schema `1.0`, an exact installation ID, the reviewed
future Linux layout, a supplied timestamp, and a public executable reference.
The sandbox root is supplied separately and must be an existing temporary
subdirectory.

Pilot configuration contains an exact application ID and target allowlist.
Pilot policy rejects unknown fields and requires local-only, read-only,
sandbox-only operation with repairs, notifications, network, process
enumeration, and systemd access disabled. Scenario input supplies a timestamp,
exact host reference, and one fictional observation per target. Secret values,
wildcards, automatic discovery, and environment-secret resolution are
unavailable.
