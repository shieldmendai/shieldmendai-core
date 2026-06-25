# ShieldMendAi Configuration

Phase 2 configuration is YAML and planning-only. The canonical safe example is
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

No adapter executes in Phase 2.

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

These are classification values only; Phase 2 performs no detection.

## Security Categories

The typed model includes operating-system and application-dependency
vulnerabilities, insecure configuration, exposed services or ports, dangerous
permissions, secret-exposure indicators, outdated software, weak TLS,
certificate problems, unauthorized file changes, suspicious processes or
service behavior, baseline violations, and unknown security findings.

These are classification values only; Phase 2 performs no security scanning.

## Policies

Repair policies use one of:

```text
observe_only
recommend
require_approval
auto_repair_low_risk
auto_repair_allowlisted
```

Action categories are modeled, not executed. There is no fix-everything mode.

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

Validation rejects duplicate or empty IDs, unsupported adapters, invalid
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
