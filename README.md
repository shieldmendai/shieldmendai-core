# ShieldMendAi

ShieldMendAi is a self-hosted reliability and security recovery platform under
active development. Its long-term mission is to detect application and
infrastructure failures, determine a policy-approved response, verify recovery,
roll back failed actions, and report sanitized incidents.

ShieldMendAi does not guarantee detection or prevention of every vulnerability,
attack, application failure, or unsafe repair condition.

## Phase 5 Status

Phase 5 adds deterministic recovery verification, explicit lifecycle
transitions, bounded retries, cooldown and backoff, circuit breakers, rollback
decisions, idempotency protection, and versioned non-secret controller state.
It preserves all Phase 2–4 behavior.

It does not monitor live systems, inspect processes, contact systemd, open
network connections, execute commands, send notifications, repair files,
restart services, change permissions, roll back deployments, apply code
patches, scan vulnerabilities, or deploy anything.

Implemented:

- typed configuration, target, policy, incident, status, and notification models;
- reliability and security category enums;
- recursive redaction utilities;
- YAML configuration validation;
- planning-only CLI output;
- typed observation requests, contexts, findings, and results;
- fixed adapter registry and capability declarations;
- simulation-only adapters for systemd, process, PID-file, HTTP, TCP,
  executable, file, JSON, YAML, and TOML targets;
- safe scenario validation and fixture-root confinement;
- safe language-independent example configuration;
- automated safety and validation tests.
- typed repair requests, policies, authorization decisions, reason codes,
  approvals, preconditions, verification plans, rollback plans, results, and
  audit events;
- exact target, adapter, action, and target/action allowlists;
- simulation-only repair planning and deterministic outcomes.
- typed recovery policies, snapshots, transitions, attempts, verification
  evaluations, rollback decisions, outcomes, and audit events;
- fixed, linear, exponential, and bounded exponential backoff;
- rolling failure windows, circuit breaking, duplicate suppression, and
  manual-intervention escalation;
- JSON-safe recovery-state serialization and inspection.

Unavailable or modeled only:

- production Linux observers; Windows, container, Kubernetes, database, and
  plugin adapters;
- production repairs, live verification, rollback execution, and notifications;
- code-repair workflow;
- Telegram, email, SMS, webhook, and local incident delivery.

## Language-Independent Design

The core is currently Python, but protected applications do not need to be
Python applications. Targets are described through operating-system and
application boundaries such as systemd units, processes, PID files, TCP,
HTTP, structured files, fixed executable checks, databases, containers,
Kubernetes resources, Windows services, and future plugins.

ShieldMendAi is Linux-first. Windows, Docker, Kubernetes, cloud VM, on-premise,
website, API, database, and background-worker support are future capabilities,
not completed integrations.

## Development Installation

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

The only runtime dependency is constrained to `PyYAML>=6.0,<7.0`.

## Safe CLI

```bash
shieldmendai --version
shieldmendai validate-config examples/shieldmendai.example.yaml
shieldmendai plan examples/shieldmendai.example.yaml
shieldmendai show-config examples/shieldmendai.example.yaml
shieldmendai list-adapters
shieldmendai inspect-scenario examples/scenarios/phase3-example.yaml
shieldmendai simulate examples/simulation-config.yaml examples/scenarios/phase3-example.yaml
shieldmendai list-repair-actions
shieldmendai inspect-repair-policy examples/repair/policy.yaml
shieldmendai authorize-repair examples/repair/config.yaml examples/repair/request.yaml examples/repair/policy.yaml
shieldmendai plan-repair examples/repair/config.yaml examples/repair/request.yaml examples/repair/policy.yaml
shieldmendai simulate-repair examples/repair/config.yaml examples/repair/request.yaml examples/repair/policy.yaml examples/repair/scenarios/success.yaml
shieldmendai inspect-recovery-policy examples/recovery/policy.yaml
shieldmendai calculate-backoff examples/recovery/policy.yaml 2
shieldmendai simulate-recovery examples/repair/config.yaml examples/repair/request.yaml examples/repair/policy.yaml examples/recovery/policy.yaml examples/recovery/scenarios/first-success.yaml
```

`plan` remains planning-only. Simulation output is explicitly labeled and
`show-config` redacts credential references without resolving environment
variables.

Without an editable installation:

```bash
PYTHONPATH=src python3 -m shieldmendai.main --version
```

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Documentation

- [Configuration and policies](docs/CONFIGURATION.md)
- [Phase 3 simulation](docs/SIMULATION.md)
- [Phase 4 repair authorization and simulation](docs/REPAIRS.md)
- [Phase 5 deterministic recovery](docs/RECOVERY.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security boundaries](docs/SECURITY_BOUNDARIES.md)
- [Extraction plan](docs/EXTRACTION_PLAN.md)
- [Codex handoff](docs/CODEX_HANDOFF.md)
- [Dedicated server plan](docs/DEDICATED_SERVER_PLAN.md)
- [Extraction manifest](extraction_manifest.json)

## Roadmap

1. Phase 1: sanitized inventory and architecture — complete.
2. Phase 2: safe standalone framework and dry-run CLI — complete.
3. Phase 3: safe observation simulations and fixture checks — complete.
4. Phase 4: deny-by-default controlled repair models and simulation-only
   allowlisted action execution — complete.
5. Phase 5: deterministic recovery verification and loop protection — complete.
6. Phase 6: redacted incident records and optional alert interfaces.
7. Later phases: production adapters, installer, expanded simulations, and
   deployment.

The exact Phase 6 task is to add redacted local incident records, retention
controls, notifier interfaces, and optional outbound alert modeling with
delivery disabled by default.

## License

MIT
