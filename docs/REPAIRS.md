# Phase 4 Repair Authorization and Simulation

Phase 4 adds deny-by-default repair authorization, planning, and deterministic
simulation. It does not add a production repair engine.

## Safety Boundary

Every request is denied unless all applicable gates pass. Missing, unknown,
expired, mismatched, ambiguous, or unsupported data denies authorization.
Target IDs, adapter types, actions, and target/action pairs require exact
matches. Empty allowlists deny execution, and wildcard or duplicate entries
are invalid.

No Phase 4 command restarts a service, restores a file, changes permissions or
ownership, rolls back a deployment, applies a code patch, sends a notification,
uses a subprocess, or accesses a network.

## Policy Modes

- `observe_only`: planning and observation only; all repair execution denied.
- `recommend`: returns a typed recommendation and denial explanation.
- `require_approval`: requires a valid matching unexpired approval.
- `auto_repair_low_risk`: permits only explicitly allowlisted informational or
  low-risk simulations.
- `auto_repair_allowlisted`: permits only exact allowlisted target/action
  pairs within the configured maximum risk.

There is no unrestricted, force, bypass, fix-everything, or repair-all mode.

## Risk and Actions

Risk levels are `informational`, `low`, `medium`, `high`, `critical`, and
`prohibited`. Unknown risk is prohibited.

The CLI action catalog reports every typed action, its risk, whether Phase 4
supports deterministic simulation, and that production execution is
unavailable. Code-patch application is prohibited. Code-patch proposal is
modeled only and has no executor.

## Approvals

Approvals contain sanitized references, not authentication secrets or personal
contact details. An approval must match request ID, action, and exact target
scope. Expired, revoked, denied, pending, mismatched, future-dated, or consumed
one-time approvals are rejected. Phase 4 does not implement authentication.

## Plans, Verification, and Rollback

Authorized plans contain typed preconditions and deterministic steps. Every
permitted simulation requires a verification plan. Actions that would mutate
state in a future phase require a rollback plan. Known-good file restoration
simulation also requires a sanitized known-good reference.

Verification and rollback outcomes come only from validated scenario files.
No real verification or rollback check is executed. A simulated verification
failure triggers the modeled rollback path; rollback failure produces
`manual_intervention_required`.

## CLI

```bash
shieldmendai list-repair-actions
shieldmendai inspect-repair-policy examples/repair/policy.yaml
shieldmendai authorize-repair examples/repair/config.yaml examples/repair/request.yaml examples/repair/policy.yaml
shieldmendai plan-repair examples/repair/config.yaml examples/repair/request.yaml examples/repair/policy.yaml
shieldmendai simulate-repair examples/repair/config.yaml examples/repair/request.yaml examples/repair/policy.yaml examples/repair/scenarios/success.yaml
```

`plan-repair` prints `SIMULATION PLANNING ONLY — NO SYSTEM CHANGES`.
`simulate-repair` prints `SIMULATION ONLY — NO LIVE REPAIR PERFORMED`.

Exit codes:

- `0`: valid authorization/planning or successful simulation.
- `1`: invalid CLI input, configuration, request, policy, or scenario.
- `2`: repair denied by policy.
- `3`: simulated action or verification failed.
- `4`: unsafe or unsupported action rejected.
- `5`: simulated rollback failed or manual intervention is required.

Existing Phase 2 and Phase 3 exit-code behavior is unchanged.

## Examples and Audit

`examples/repair/scenario-catalog.yaml` records seventeen fictional cases,
including policy denial, approval failures, allowlist failures, risk and loop
gates, verification/rollback outcomes, and prohibited code-patch application.
Executable scenario files cover success, verification failure with simulated
rollback success, and rollback failure.

Returned audit events and attempt records contain typed identifiers, policy and
reason references, action risk, simulation state, and outcomes. They contain
no complete evidence, credentials, or remote telemetry and are not persisted
outside caller-controlled test locations.

## Production Capabilities Unavailable

No real repair is implemented. No service restart, file restoration,
permission or ownership change, deployment rollback, code patch, verification
probe, notification, network operation, subprocess, or dedicated-server
deployment occurs in Phase 4.

Unrestricted automatic repair is prohibited because target ambiguity,
unbounded scope, absent verification, missing rollback, and approval bypasses
can convert recovery software into a destructive control plane.

## Exact Phase 5 Task

Implement recovery verification and loop protection using deterministic
simulation first: bounded retry budgets, cooldown and backoff evaluation,
circuit breakers, post-repair verification state transitions, rollback
decision rules, and non-secret controller state. Phase 5 must not add
production mutation, live observers, notification delivery, or deployment.
