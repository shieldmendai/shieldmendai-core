# ShieldMendAi

ShieldMendAi is a self-hosted reliability and security recovery platform under
active development. Its long-term mission is to detect application and
infrastructure failures, determine a policy-approved response, verify recovery,
roll back failed actions, and report sanitized incidents.

ShieldMendAi does not guarantee detection or prevention of every vulnerability,
attack, application failure, or unsafe repair condition.

## Phase 3 Status

Phase 3 provides an installable Python framework for configuration validation,
dry-run planning, deterministic observation simulations, and fixture-confined
read-only file checks. It does not monitor live systems, inspect processes,
contact systemd, open network connections, execute commands, send
notifications, repair files, restart services, scan vulnerabilities, modify
source code, or deploy anything.

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

Unavailable or modeled only:

- production Linux observers; Windows, container, Kubernetes, database, and
  plugin adapters;
- controlled repairs, verification, rollback, and notifications;
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
   allowlisted action execution.
5. Later phases: production adapters, verification and loop protection,
   incidents and notifications, installer, simulations, and deployment.

The exact Phase 4 task is to add deny-by-default repair authorization and
simulation-only executors for explicit allowlisted actions. No production
mutation or notification delivery belongs in Phase 4.

## License

MIT
