# ShieldMendAi

ShieldMendAi is a self-hosted reliability and security recovery platform under
active development. Its long-term mission is to detect application and
infrastructure failures, determine a policy-approved response, verify recovery,
roll back failed actions, and report sanitized incidents.

ShieldMendAi does not guarantee detection or prevention of every vulnerability,
attack, application failure, or unsafe repair condition.

## Phase 2 Status

Phase 2 provides an installable Python framework for configuration validation
and dry-run planning. It does not monitor systems, inspect processes, contact
systemd, open network connections, send notifications, repair files, restart
services, scan vulnerabilities, modify source code, or deploy anything.

Implemented:

- typed configuration, target, policy, incident, status, and notification models;
- reliability and security category enums;
- recursive redaction utilities;
- YAML configuration validation;
- planning-only CLI output;
- safe language-independent example configuration;
- automated safety and validation tests.

Modeled only:

- Linux, Windows, container, Kubernetes, database, and plugin adapters;
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
```

`plan` is always planning-only in Phase 2. `show-config` redacts credential
references and never resolves environment variables.

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
- [Architecture](docs/ARCHITECTURE.md)
- [Security boundaries](docs/SECURITY_BOUNDARIES.md)
- [Extraction plan](docs/EXTRACTION_PLAN.md)
- [Codex handoff](docs/CODEX_HANDOFF.md)
- [Dedicated server plan](docs/DEDICATED_SERVER_PLAN.md)
- [Extraction manifest](extraction_manifest.json)

## Roadmap

1. Phase 1: sanitized inventory and architecture — complete.
2. Phase 2: safe standalone framework and dry-run CLI — complete.
3. Phase 3: generic read-only monitoring and detection adapters.
4. Later phases: controlled repair, verification and loop protection,
   incidents and notifications, installer, simulations, and deployment.

The exact Phase 3 task is to implement read-only adapter interfaces and fake
test adapters for systemd, file, process, command, HTTP, and TCP observations.
No repair execution belongs in Phase 3.

## License

MIT
