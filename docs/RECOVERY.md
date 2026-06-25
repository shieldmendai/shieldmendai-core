# Phase 5 Deterministic Recovery

Phase 5 adds a typed, simulation-only recovery controller. It consumes an
authorized Phase 4 repair plan and fictional scenario outcomes. It never calls
a live observer, executor, rollback adapter, service manager, process API,
network client, notifier, or deployment interface.

## Lifecycle

The explicit lifecycle is:

```text
idle -> finding_detected -> authorization_required
authorization_required -> authorized | authorization_denied
authorized -> waiting_for_cooldown | ready_for_attempt
ready_for_attempt -> simulated_repair_running -> awaiting_verification
awaiting_verification -> verification_succeeded | verification_failed
verification_failed -> retry_scheduled | rollback_required | circuit_open |
  manual_intervention_required
rollback_required -> simulated_rollback_running
simulated_rollback_running -> rollback_succeeded | rollback_failed
rollback_succeeded -> awaiting_verification
verification_succeeded -> resolved
```

Open circuits can permit one bounded half-open attempt only after the supplied
reset timestamp. Terminal authorization-denied, resolved, abandoned, and
manual-intervention states cannot silently restart. Unknown states and invalid
transitions are rejected.

## Policies and Loop Protection

Retry budgets separately bound repair, verification, and rollback attempts.
Unknown outcomes are nonretryable. Attempt counts can be scoped per incident
and target. Cooldown uses a supplied timestamp and supports per-target,
per-incident, per-action, and per-target/action scopes; bypass is always
disabled.

Backoff supports fixed, linear, exponential, and bounded exponential
calculations. Jitter is disabled. Values are finite, bounded, and checked for
timestamp overflow.

The circuit breaker tracks sanitized repair, verification, rollback, and
optional authorization failures in a deterministic rolling window. It has
closed, open, and half-open states. Authorization denials do not count by
default. Open and half-open attempt budgets deny loops.

Exact plan IDs, request/action pairs, and deterministic attempt IDs provide
duplicate and replay protection. Wildcards and unknown idempotency states are
not accepted. Phase 4 one-time request and approval checks remain authoritative.

## Verification and Rollback

Verification evaluates only supplied statuses: pending, passed, failed,
inconclusive, skipped, timed out, and unsupported. Missing, incomplete,
incompatible, inconclusive, or unknown verification never establishes
success.

Rollback decisions consider availability, a known-good reference, remaining
budget, approval validity, and policy. A simulated rollback success enters
post-rollback verification; it does not resolve the incident. Missing or
exhausted rollback escalates to manual intervention.

## State

Recovery snapshots use versioned JSON-safe data. Parsing rejects unknown schema
versions, missing or extra fields, invalid enums or timestamps, negative
counters, duplicate IDs, impossible state combinations, `simulation: false`,
and credential-like fields or values. No evidence payloads or credentials are
serialized. Tests write snapshots only inside temporary directories.

## CLI

```bash
shieldmendai inspect-recovery-policy examples/recovery/policy.yaml
shieldmendai calculate-backoff examples/recovery/policy.yaml 2
shieldmendai simulate-recovery \
  examples/repair/config.yaml \
  examples/repair/request.yaml \
  examples/repair/policy.yaml \
  examples/recovery/policy.yaml \
  examples/recovery/scenarios/first-success.yaml
shieldmendai inspect-recovery-state STATE.json
shieldmendai inspect-circuit STATE.json
```

Exit codes:

- `0`: deterministic recovery resolved successfully, or inspection/calculation succeeded.
- `1`: invalid policy, scenario, state, or other input.
- `2`: denied by authorization, cooldown, duplicate protection, retry gate, or open circuit.
- `3`: verification failed while another modeled step remains possible, including post-rollback verification.
- `4`: unsafe or unsupported operation rejected.
- `5`: rollback failed or manual intervention is required.
- `6`: circuit breaker opened.
- `7`: invalid lifecycle transition.

All recovery output is marked simulation-only. No live repair or verification
occurs; no service is restarted; no file is restored; no permission,
ownership, deployment, repository, or database change occurs; no network
access or notification occurs; and no production controller is enabled.

The exact Phase 6 task is to add redacted local incident records, retention
controls, notifier interfaces, and optional outbound alert modeling with
delivery disabled by default. Phase 6 must not enable production recovery,
live observers, or mandatory network access.
