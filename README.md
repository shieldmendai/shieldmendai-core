# ShieldMendAi

ShieldMendAi is a self-hosted reliability and security recovery platform under
active development. Its long-term mission is to detect application and
infrastructure failures, determine a policy-approved response, verify recovery,
roll back failed actions, and report sanitized incidents.

ShieldMendAi does not guarantee detection or prevention of every vulnerability,
attack, application failure, or unsafe repair condition.

## Phase 6 Status

Phase 6 adds sanitized versioned incident records, explicit incident
lifecycles, fixture-confined local storage, integrity checks, retention preview
and simulation, fixed notifier interfaces, routing, safe templates, duplicate
suppression, cooldown and attempt budgets, and deterministic Telegram, email,
SMS, webhook, and local-alert simulations. It preserves all Phase 2–5
behavior.

It sends no real notification, resolves no credential, opens no network
connection, creates no production incident directory, deletes no production
record, and performs no live monitoring, repair, recovery, or deployment.

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
- typed incident records, timelines, correlation, lifecycle transitions,
  version metadata, and sanitized checksums;
- temporary-root-confined incident JSON storage and deterministic retention
  preview/fixture simulation;
- fixed simulated notifier registry and provider capabilities;
- severity, event, status, and escalation routing;
- allowlisted message templates, redaction, escaping, length bounds, and
  visible truncation;
- duplicate-alert suppression, cooldowns, attempt budgets, delivery results,
  and notification audit records.

Unavailable or modeled only:

- production Linux observers; Windows, container, Kubernetes, database, and
  plugin adapters;
- production repairs, live verification, rollback execution, production
  incident storage, production retention deletion, and real notifications;
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
shieldmendai list-notifiers
shieldmendai inspect-notification-policy examples/notifications/policy.yaml
shieldmendai inspect-incident examples/incidents/incident-low.json
shieldmendai render-notification examples/incidents/incident-low.json examples/notifications/policy.yaml examples/notifications/template.yaml
shieldmendai simulate-notification examples/incidents/incident-low.json examples/notifications/policy.yaml examples/notifications/scenario.yaml --template-path examples/notifications/template.yaml
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
- [Phase 6 incidents, retention, and notification simulation](docs/INCIDENTS_AND_NOTIFICATIONS.md)
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
6. Phase 6: redacted incident records, retention, and notification
   simulations — complete.
7. Phase 7: controlled dedicated-server sandbox installation and a local-only,
   read-only Linux observation pilot.

The exact Phase 7 task is to create a controlled dedicated-server sandbox
installation and a local-only, read-only Linux observation pilot for
ShieldMendAi. Phase 7 must include no repairs, service restarts, notification
delivery, customer deployment, or private-source access.

## License

MIT
