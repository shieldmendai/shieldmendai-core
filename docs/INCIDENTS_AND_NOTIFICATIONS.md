# Phase 6 Incidents, Retention, and Notification Simulation

Phase 6 adds versioned, sanitized incident records and deterministic
notification simulations. It does not create a production incident directory,
delete production data, resolve credentials, or contact a provider.

## Incident records and lifecycle

`IncidentRecord` contains application and target references, category,
severity, confidence, lifecycle status, sanitized summary and description,
structured evidence references, recovery references, outcome, timeline events,
correlation metadata, notification summary, and simulation markers.

Lifecycle states are `detected`, `open`, `acknowledged`, `investigating`,
`remediation_planned`, `simulated_recovery_running`,
`monitoring_verification`, `resolved`, `closed`, `suppressed`, `duplicate`,
and `manual_intervention_required`. Transitions use an explicit allowlist.
Closed incidents cannot reopen. A resolved incident can reopen only through an
explicit new-event transition. Duplicate incidents require an exact canonical
incident reference, and suppressed incidents require a reason code.

Every transition appends a typed, sanitized, chronological event. Unknown
states and event types, duplicate event IDs, malformed timestamps, negative
counters, and missing transition data are rejected.

## Correlation and integrity

Correlation fingerprints use normalized application ID, target ID, category,
adapter type, and a sanitized finding fingerprint. Matching is exact; prefixes
and wildcards are not used. Different application scopes never correlate.

Stored records include schema version, record version, predecessor version,
record ID, timestamps, and a SHA-256 checksum of canonical sanitized JSON.
Unknown schemas, checksum changes, and version rollback are rejected.
Cryptographic signing and external key management are not implemented.

## Safe local store

`LocalIncidentStore` accepts only an explicitly supplied, existing absolute
directory beneath the operating system temporary directory. It rejects server
roots, traversal, unsafe symlinks, and private-source references. Atomic JSON
writes stay within that root. There is no default production incident path,
external database, pickle, shell command, or background writer.

## Retention

Retention policies model maximum age, count, and bytes plus protections for
unresolved incidents, manual-intervention incidents, minimum severity, and
latest versions. Decisions include retain, eligible for removal, protected
states, invalid record, and manual review.

Preview is the default and modifies nothing. Explicit fixture-removal
simulation is available only under a validated temporary root and never claims
production deletion. All decisions use a supplied deterministic timestamp.

## Notification providers and routing

The fixed notifier registry contains Telegram, email, SMS, webhook, and local
simulation adapters. External providers declare that they require network in a
future production implementation, while `network_used_in_phase6` and
`production_delivery_available` are false. Secret resolution is unavailable.

Routing can select exact configured channels by severity, event, status, and
escalation condition. Disabled policies, suppressed targets or categories,
minimum severity, unavailable channels, and empty routes produce no delivery.
Provider failures are isolated, so one simulated failure does not block other
channels.

Configuration contains environment-variable names and destination references
only. Direct tokens, passwords, account identifiers, webhook URLs,
authenticated URLs, wildcard recipients, invalid ports, invalid timeouts, and
unknown providers are rejected. Environment variables are never read.

## Templates, suppression, cooldowns, and limits

Templates use Python-style braces with a fixed allowlist:
`incident_id`, `application_id`, `target_id`, `severity`, `category`, `status`,
`summary`, `event_type`, `recovery_state`, `final_outcome`,
`manual_intervention_required`, and `timestamp`.

Attribute access, indexing, conversions, filters, file inclusion, environment
expansion, `eval`, and `exec` are unavailable. Rendered messages are sanitized,
provider-escaped where applicable, length-bounded, visibly truncated, marked
as simulation, and exclude complete evidence objects.

Duplicate suppression uses exact sanitized fingerprints and supplied
timestamps. Explicit policy can let severity or manual-intervention escalation
override duplicate suppression. Cooldown and per-channel/per-incident attempt
budgets produce deterministic suppression and next-eligible timestamps. There
are no sleeps or background schedulers.

## CLI and exit codes

Commands:

```text
shieldmendai list-notifiers
shieldmendai inspect-notification-policy POLICY_PATH
shieldmendai inspect-incident INCIDENT_PATH
shieldmendai inspect-incident-store STORE_ROOT
shieldmendai render-notification INCIDENT_PATH POLICY_PATH TEMPLATE_PATH
shieldmendai simulate-notification INCIDENT_PATH POLICY_PATH SCENARIO_PATH
shieldmendai preview-retention STORE_ROOT POLICY_PATH
shieldmendai simulate-retention STORE_ROOT POLICY_PATH SCENARIO_PATH
```

Exit codes are: `0` valid/successful simulation, `1` invalid input, `2`
suppressed or no route, `3` simulated provider failure, `4` production
delivery or unsupported operation rejected, `5` incident integrity/manual
review, `6` unsafe retention/store root, and `7` invalid incident transition.

No real Telegram message, email, SMS, or webhook request is sent. No provider
credential is resolved. No external network connection is made. No production
incident directory is created. No production retention deletion or live
repair/recovery occurs.

## Phase 7 reuse

The Phase 7 Linux pilot reuses `LocalIncidentStore` only inside a validated
temporary sandbox. Unhealthy fixture-backed findings create sanitized
checksummed incidents, and later healthy fixture rechecks can resolve open
pilot incidents. Notification delivery remains disabled and no production
incident directory is created.
