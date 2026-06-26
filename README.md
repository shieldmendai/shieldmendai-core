# ShieldMendAi

ShieldMendAi is a self-hosted reliability and security recovery platform under
active development. Its long-term mission is to detect application and
infrastructure failures, determine a policy-approved response, verify recovery,
roll back failed actions, and report sanitized incidents.

ShieldMendAi does not guarantee detection or prevention of every vulnerability,
attack, application failure, or unsafe repair condition.

## Phase 8 Status

Phase 8 is a dedicated-server read-only canary package with a deployment
readiness fix. A manual readiness audit found the first Phase 8 package was not
live-ready because launcher/config file modes and the isolated runtime
installation were incomplete. The audit caught those blockers before any live
installation.

The current package enforces actual temporary-root file modes, supports
`python3 -m shieldmendai`, validates and installs a local ShieldMendAi wheel
into `/opt/shieldmendai/venv` with `--no-index --no-deps`, renders systemd
units that execute `/opt/shieldmendai/venv/bin/shieldmendai`, and documents the
operator-reviewed service-user and ownership commands.

It performs no dedicated-server contact, SSH, real installation, user creation,
ownership change, systemd operation, live observation, repair, notification,
network connection, customer deployment, or production-path modification during
development and tests.

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
- controlled sandbox installation and preview-first fixture uninstallation;
- least-privilege service-user, ownership, permission, filesystem, and systemd
  template plans;
- exact local target allowlists and fixture-backed one-cycle Linux pilot;
- disabled production Linux adapters and local observation incident linkage.

Unavailable or modeled only:

- production Linux observers; Windows, container, Kubernetes, database, and
  plugin adapters;
- production repairs, live verification, rollback execution, production
  incident storage, production retention deletion, and real notifications;
- code-repair workflow;
- Telegram, email, SMS, webhook, and local incident delivery.
- real installation, Linux user creation, systemd installation or service
  control, and live Linux observation.

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
shieldmendai inspect-installation-plan examples/installation/plan.yaml
shieldmendai render-systemd-units examples/installation/plan.yaml
shieldmendai inspect-pilot-policy examples/pilot/policy.yaml
shieldmendai list-linux-observers
shieldmendai inspect-canary-config examples/canary/dedicated-canary.yaml
shieldmendai render-canary-systemd-units
shieldmendai show-canary-service-user-plan
shieldmendai canary-runtime-install-preview /absolute/path/to/shieldmendai-0.4.0-py3-none-any.whl --runtime-path /tmp/shieldmendai-runtime
```

`plan` remains planning-only. Simulation output is explicitly labeled and
`show-config` redacts credential references without resolving environment
variables.

Without an editable installation:

```bash
PYTHONPATH=src python3 -m shieldmendai --version
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
- [Phase 7 installation sandbox and Linux pilot](docs/INSTALLATION_AND_LINUX_PILOT.md)
- [Phase 8 dedicated canary runbook](docs/PHASE8_CANARY_RUNBOOK.md)
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
7. Phase 7: controlled installation sandbox and local-only read-only Linux
   pilot — complete.
8. Phase 8: dedicated test-server read-only canary deployment package —
   prepared for manual execution.

Phase 8 has not been deployed. The dedicated server was not contacted during
the readiness fix. The package is read-only observation only: no repairs, no
restarts by ShieldMendAi, no notifications, no customer deployment, no
trading-bot dependency, no code rewriting, and no access to the prohibited
unrelated private source tree.

## License

MIT
